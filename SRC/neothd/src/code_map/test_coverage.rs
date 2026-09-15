//! Bounded, generation-bound observed test evidence. Empty never means absent.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use super::graph::{EdgeConfidenceTier, EdgeKind};
use super::impact::{ImpactNodeId, ImpactResult};
use super::persist::{index_freshness_receipt, root_snapshot_complete};
use super::persist::{root_graph_generation, root_index_generation};
use super::root_identity::CanonicalRepoRoot;
use std::path::Path;

pub const DEFAULT_MAX_TEST_DEPTH: usize = 3;
pub const DEFAULT_MAX_TEST_NODES: usize = 2_000;
const MAX_TEST_EDGE_ROWS: usize = 20_000;
const MAX_TEST_EDGE_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_TEST_RESULT_TEXT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TestCoverageNode {
    pub file: String,
    pub symbol: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestCoverageProvenance {
    FrameworkAndConventionalPath,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedTest {
    pub test: TestCoverageNode,
    pub target: TestCoverageNode,
    pub confidence: u8,
    pub confidence_tier: EdgeConfidenceTier,
    pub provenance: TestCoverageProvenance,
    pub distance: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestCoverageOptions {
    pub max_depth: usize,
    pub max_nodes: usize,
}
impl Default for TestCoverageOptions {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_TEST_DEPTH,
            max_nodes: DEFAULT_MAX_TEST_NODES,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestCoverageUncertainty {
    pub no_observed_test: bool,
    pub stale_graph: bool,
    pub partial_graph: bool,
    pub depth_capped: bool,
    pub node_capped: bool,
    pub edge_rows_capped: bool,
    pub unresolved_or_ambiguous: bool,
    pub unsupported_or_unclassified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestCoverageResult {
    pub root: String,
    pub seed: TestCoverageNode,
    pub index_generation: i64,
    pub graph_generation: i64,
    pub observed_tests: Vec<ObservedTest>,
    /// Aggregate-only exclusions from this same persisted root/generation.
    /// They are root-wide classifier facts, not an assertion that any one
    /// impacted declaration has a missing test.
    pub exclusion_provenance: super::graph::TestEvidenceExclusionSummary,
    pub uncertainty: TestCoverageUncertainty,
}

/// Source-state receipt retained even when the supplied impact result is
/// rejected. This prevents an error fallback from being mistaken for a gap.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactTestGapInputProvenance {
    pub source_index_generation: i64,
    pub source_graph_generation: i64,
    pub stale: bool,
    pub truncated: bool,
    pub budget_truncated: bool,
    pub evidence_truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactTestGapRejection {
    Stale,
    Truncated,
    BudgetTruncated,
    EvidenceTruncated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactTestGapOutcome {
    Complete,
    RejectedInput(ImpactTestGapRejection),
}

/// A concrete CRG-02 identity is never folded into `(file, symbol)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactTestGapIdentity {
    Exact,
    UnresolvedOrAmbiguous,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactTestGapNodeResult {
    pub impact_node: ImpactNodeId,
    pub identity: ImpactTestGapIdentity,
    /// None means identity evidence was missing, ambiguous, or the shared
    /// work budget was exhausted before a coverage query could be made.
    pub coverage: Option<TestCoverageResult>,
}

/// One whole-query work receipt. The counter includes physical edge loading,
/// traversal, direct tested-by probes, and emitted observations.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactTestGapWorkBudget {
    pub max_units: usize,
    pub consumed_units: usize,
    pub remaining_units: usize,
    pub capped: bool,
    pub root_edge_loads: usize,
    pub root_edges_loaded: usize,
    pub root_edge_rows_read: usize,
    pub traversal_nodes: usize,
    pub traversal_edges: usize,
    pub tested_by_probes: usize,
    pub observed_test_rows: usize,
}

#[derive(Clone, Debug)]
struct SharedImpactTestGapBudget {
    receipt: ImpactTestGapWorkBudget,
}

impl SharedImpactTestGapBudget {
    fn new(max_units: usize) -> Self {
        Self {
            receipt: ImpactTestGapWorkBudget {
                max_units,
                remaining_units: max_units,
                ..Default::default()
            },
        }
    }

    fn charge(&mut self) -> bool {
        if self.receipt.remaining_units == 0 {
            self.receipt.capped = true;
            return false;
        }
        self.receipt.consumed_units += 1;
        self.receipt.remaining_units -= 1;
        true
    }

    fn finish(self) -> ImpactTestGapWorkBudget {
        self.receipt
    }
}

/// One CRG-02-bound test-gap receipt. Empty observations remain evidence only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactTestGapResult {
    pub root: String,
    pub index_generation: i64,
    pub graph_generation: i64,
    pub impact_digest: String,
    pub input: ImpactTestGapInputProvenance,
    pub outcome: ImpactTestGapOutcome,
    pub per_node: Vec<ImpactTestGapNodeResult>,
    pub impact_partial: bool,
    pub work_budget: ImpactTestGapWorkBudget,
    /// Absent only when typed input rejection prevented every database read.
    pub exclusion_provenance: Option<super::graph::TestEvidenceExclusionSummary>,
    pub no_observed_test_is_not_absence: bool,
}

fn impact_input_provenance(impact: &ImpactResult) -> ImpactTestGapInputProvenance {
    ImpactTestGapInputProvenance {
        source_index_generation: impact.index_generation,
        source_graph_generation: impact.graph_generation,
        stale: impact.stale,
        truncated: impact.truncated,
        budget_truncated: impact.budget_truncated,
        evidence_truncated: impact.evidence_truncated,
    }
}

fn rejected_impact_input(impact: &ImpactResult) -> Option<ImpactTestGapRejection> {
    if impact.stale {
        Some(ImpactTestGapRejection::Stale)
    } else if impact.truncated {
        Some(ImpactTestGapRejection::Truncated)
    } else if impact.budget_truncated {
        Some(ImpactTestGapRejection::BudgetTruncated)
    } else if impact.evidence_truncated {
        Some(ImpactTestGapRejection::EvidenceTruncated)
    } else {
        None
    }
}

fn exact_impact_identity(
    conn: &Connection,
    root: &str,
    node: &ImpactNodeId,
    budget: &mut SharedImpactTestGapBudget,
) -> Result<ImpactTestGapIdentity> {
    if !budget.charge() {
        return Ok(ImpactTestGapIdentity::UnresolvedOrAmbiguous);
    }
    let (exact, same_coverage_key): (i64, i64) = conn
        .query_row(
            "SELECT \
             COALESCE(SUM(CASE WHEN s.line = ?4 AND s.kind = ?5 THEN 1 ELSE 0 END), 0), \
             COUNT(*) \
         FROM code_map_files f \
         JOIN code_map_symbols s ON s.file_id = f.id \
         WHERE f.root = ?1 AND f.path = ?2 AND s.name = ?3",
            rusqlite::params![
                root,
                &node.file,
                &node.symbol,
                i64::from(node.line),
                &node.kind
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("resolve exact impact declaration identity")?;
    Ok(if exact == 1 && same_coverage_key == 1 {
        ImpactTestGapIdentity::Exact
    } else {
        ImpactTestGapIdentity::UnresolvedOrAmbiguous
    })
}

#[allow(clippy::too_many_arguments)] // Keep root, generations, evidence and shared budget explicit.
fn coverage_for_exact_impact_node(
    root: &str,
    seed: TestCoverageNode,
    index_generation: i64,
    graph_generation: i64,
    partial_graph: bool,
    edge_rows_capped: bool,
    exclusion_provenance: &super::graph::TestEvidenceExclusionSummary,
    incoming_calls: &BTreeMap<String, Vec<TestCoverageNode>>,
    tested_by: &BTreeMap<TestCoverageNode, Vec<super::graph::CodeEdge>>,
    options: &TestCoverageOptions,
    budget: &mut SharedImpactTestGapBudget,
) -> TestCoverageResult {
    let mut uncertainty = TestCoverageUncertainty {
        stale_graph: index_generation < 0 || graph_generation != index_generation,
        partial_graph,
        edge_rows_capped,
        ..Default::default()
    };
    let mut targets = BTreeMap::from([(seed.clone(), 0usize)]);
    let mut frontier = VecDeque::from([(seed.clone(), 0usize)]);
    while let Some((node, distance)) = frontier.pop_front() {
        if !budget.charge() {
            uncertainty.node_capped = true;
            break;
        }
        budget.receipt.traversal_nodes += 1;
        let Some(incoming) = incoming_calls.get(&node.symbol) else {
            continue;
        };
        if distance >= options.max_depth {
            if incoming.iter().any(|caller| !targets.contains_key(caller)) {
                uncertainty.depth_capped = true;
            }
            continue;
        }
        for caller in incoming {
            if targets.contains_key(caller) {
                continue;
            }
            if !budget.charge() {
                uncertainty.node_capped = true;
                break;
            }
            budget.receipt.traversal_edges += 1;
            uncertainty.unresolved_or_ambiguous = true;
            targets.insert(caller.clone(), distance + 1);
            frontier.push_back((caller.clone(), distance + 1));
        }
        if uncertainty.node_capped {
            break;
        }
    }
    let mut observed = BTreeSet::new();
    let mut result_text = 0usize;
    for (target, distance) in targets {
        let Some(edges) = tested_by.get(&target) else {
            continue;
        };
        for edge in edges {
            if !budget.charge() {
                uncertainty.node_capped = true;
                break;
            }
            budget.receipt.tested_by_probes += 1;
            let bytes = edge
                .from_file
                .len()
                .checked_add(edge.from_symbol.len())
                .and_then(|value| value.checked_add(edge.to_name.len()))
                .and_then(|value| {
                    value.checked_add(edge.target_file.as_ref().map_or(0, String::len))
                });
            let Some(bytes) = bytes else {
                uncertainty.node_capped = true;
                break;
            };
            let Some(next_text) = result_text.checked_add(bytes) else {
                uncertainty.node_capped = true;
                break;
            };
            if next_text > MAX_TEST_RESULT_TEXT_BYTES {
                uncertainty.node_capped = true;
                break;
            }
            result_text = next_text;
            if edge.confidence != EdgeConfidenceTier::RESOLVED_CONFIDENCE
                || edge.confidence_tier != EdgeConfidenceTier::Resolved
            {
                uncertainty.unresolved_or_ambiguous = true;
                continue;
            }
            let Some(target_file) = edge.target_file.clone() else {
                uncertainty.unresolved_or_ambiguous = true;
                continue;
            };
            let observation = (
                edge.from_file.clone(),
                edge.from_symbol.clone(),
                edge.to_name.clone(),
                target_file,
                distance,
            );
            if !observed.contains(&observation) {
                if !budget.charge() {
                    uncertainty.node_capped = true;
                    break;
                }
                observed.insert(observation);
                budget.receipt.observed_test_rows += 1;
            }
        }
        if uncertainty.node_capped {
            break;
        }
    }
    let observed_tests: Vec<_> = observed
        .into_iter()
        .map(|(file, symbol, name, target_file, distance)| ObservedTest {
            test: TestCoverageNode { file, symbol },
            target: TestCoverageNode {
                file: target_file,
                symbol: name,
            },
            confidence: EdgeConfidenceTier::RESOLVED_CONFIDENCE,
            confidence_tier: EdgeConfidenceTier::Resolved,
            provenance: TestCoverageProvenance::FrameworkAndConventionalPath,
            distance,
        })
        .collect();
    uncertainty.no_observed_test = observed_tests.is_empty();
    uncertainty.unsupported_or_unclassified = uncertainty.partial_graph
        || uncertainty.stale_graph
        || uncertainty.edge_rows_capped
        || uncertainty.node_capped
        || exclusion_provenance.capped
        || (uncertainty.no_observed_test
            && (uncertainty.unresolved_or_ambiguous
                || !exclusion_provenance.categories.is_empty()));
    TestCoverageResult {
        root: root.to_owned(),
        seed,
        index_generation,
        graph_generation,
        observed_tests,
        exclusion_provenance: exclusion_provenance.clone(),
        uncertainty,
    }
}

/// Bind test discovery to the exact canonical CRG-02 result. Stale, truncated,
/// or cap-truncated inputs return a typed fail-closed receipt without querying.
pub fn test_gap_for_impact(
    conn: &Connection,
    impact: &ImpactResult,
    options: TestCoverageOptions,
) -> Result<ImpactTestGapResult> {
    ensure!(
        options.max_nodes > 0 && options.max_nodes <= MAX_TEST_EDGE_ROWS,
        "impact test-gap max_nodes must be 1..={MAX_TEST_EDGE_ROWS}"
    );
    let input = impact_input_provenance(impact);
    if let Some(rejection) = rejected_impact_input(impact) {
        return Ok(ImpactTestGapResult {
            root: impact.root.clone(),
            index_generation: impact.index_generation,
            graph_generation: impact.graph_generation,
            impact_digest: impact.digest.clone(),
            input,
            outcome: ImpactTestGapOutcome::RejectedInput(rejection),
            per_node: Vec::new(),
            impact_partial: true,
            work_budget: SharedImpactTestGapBudget::new(options.max_nodes).finish(),
            exclusion_provenance: None,
            no_observed_test_is_not_absence: true,
        });
    }
    let canonical = CanonicalRepoRoot::discover(Path::new(&impact.root))?;
    ensure!(
        canonical.display() == impact.root,
        "impact result root is not the active canonical root"
    );
    let persisted_identity: Option<String> = conn
        .query_row(
            "SELECT root_identity FROM code_map_roots WHERE root = ?1",
            rusqlite::params![&impact.root],
            |row| row.get(0),
        )
        .optional()
        .context("read persisted physical impact root identity")?
        .flatten();
    ensure!(
        persisted_identity.as_deref() == Some(canonical.identity().as_str()),
        "physical impact root changed from the persisted snapshot"
    );
    let complete_before = root_snapshot_complete(conn, &impact.root)?;
    ensure!(complete_before, "impact root snapshot is partial");
    let freshness_before = index_freshness_receipt(conn, &impact.root)?;
    ensure!(!freshness_before.stale, "impact root index is stale");
    let index = root_index_generation(conn, &impact.root)?.context("impact root disappeared")?;
    let graph = root_graph_generation(conn, &impact.root)?.context("impact root disappeared")?;
    ensure!(
        index == impact.index_generation && graph == impact.graph_generation && index == graph,
        "impact generation binding is stale"
    );
    // One budget covers every database row loaded, identity lookup, traversal
    // step, direct-test probe, and output row across the entire impact result.
    let mut budget = SharedImpactTestGapBudget::new(options.max_nodes);
    // The loader reads one sentinel row to detect truncation. Reserve its unit
    // before issuing the query so physical SQLite reads cannot exceed the
    // caller's whole-query budget.
    // Keep four units after a capped root read: selection, exact identity,
    // one traversal step, and one direct-test probe can still produce a
    // calibrated partial receipt instead of spending the entire budget on
    // materialization.
    let edge_limit = budget
        .receipt
        .remaining_units
        .saturating_sub(5)
        .min(MAX_TEST_EDGE_ROWS);
    let (edges, edge_rows_capped, _) = super::persist::load_edges_for_root_bounded_with_text_limit(
        conn,
        &impact.root,
        edge_limit,
        MAX_TEST_EDGE_TEXT_BYTES,
    )?;
    budget.receipt.root_edge_loads = 1;
    budget.receipt.root_edges_loaded = edges.len();
    let sentinel_rows = if edge_rows_capped { 1 } else { 0 };
    let root_edge_rows_read = edges
        .len()
        .checked_add(sentinel_rows)
        .context("root edge read count overflow")?;
    budget.receipt.root_edge_rows_read = root_edge_rows_read;
    for _ in 0..root_edge_rows_read {
        if !budget.charge() {
            bail!("shared impact test-gap budget exhausted while accounting root edges");
        }
    }
    let mut incoming_calls: BTreeMap<String, Vec<TestCoverageNode>> = BTreeMap::new();
    let mut tested_by: BTreeMap<TestCoverageNode, Vec<super::graph::CodeEdge>> = BTreeMap::new();
    for edge in edges {
        match edge.kind {
            EdgeKind::Calls => incoming_calls
                .entry(edge.to_name.clone())
                .or_default()
                .push(TestCoverageNode {
                    file: edge.from_file.clone(),
                    symbol: edge.from_symbol.clone(),
                }),
            EdgeKind::TestedBy => {
                if let Some(target_file) = edge.target_file.clone() {
                    tested_by
                        .entry(TestCoverageNode {
                            file: target_file,
                            symbol: edge.to_name.clone(),
                        })
                        .or_default()
                        .push(edge);
                }
            }
            _ => {}
        }
    }
    // Preserve a small reserve for identity/traversal/output. The provenance
    // query itself receives every other remaining unit and returns a capped,
    // explicitly non-total aggregate when that is insufficient.
    let provenance_budget = budget.receipt.remaining_units.saturating_sub(8);
    let exclusion_provenance = if provenance_budget == 0 {
        super::graph::TestEvidenceExclusionSummary {
            capped: true,
            ..Default::default()
        }
    } else {
        let summary = super::persist::root_test_evidence_exclusion_summary_bounded(
            conn,
            &impact.root,
            provenance_budget,
        )?;
        for _ in 0..summary.work_units {
            if !budget.charge() {
                bail!(
                    "shared impact test-gap budget exhausted while accounting exclusion provenance"
                );
            }
        }
        summary
    };
    let mut nodes = BTreeSet::new();
    let mut coverage_key_counts = BTreeMap::<TestCoverageNode, usize>::new();
    for impacted in &impact.impacted_nodes {
        ensure!(
            impacted.node.root == impact.root,
            "impact node crosses canonical root"
        );
        let coverage_key = TestCoverageNode {
            file: impacted.node.file.clone(),
            symbol: impacted.node.symbol.clone(),
        };
        let count = coverage_key_counts.entry(coverage_key).or_default();
        *count = count
            .checked_add(1)
            .context("impact identity collision count overflow")?;
        nodes.insert(impacted.node.clone());
    }
    let mut impact_partial = edge_rows_capped;
    impact_partial |= exclusion_provenance.capped;
    let mut per_node = Vec::new();
    for impact_node in nodes {
        if !budget.charge() {
            impact_partial = true;
            break;
        }
        let seed = TestCoverageNode {
            file: impact_node.file.clone(),
            symbol: impact_node.symbol.clone(),
        };
        let identity = if coverage_key_counts.get(&seed).copied().unwrap_or(0) > 1 {
            ImpactTestGapIdentity::UnresolvedOrAmbiguous
        } else {
            exact_impact_identity(conn, &impact.root, &impact_node, &mut budget)?
        };
        if identity != ImpactTestGapIdentity::Exact {
            impact_partial = true;
            per_node.push(ImpactTestGapNodeResult {
                impact_node,
                identity,
                coverage: None,
            });
            continue;
        }
        if budget.receipt.remaining_units == 0 {
            impact_partial = true;
            break;
        }
        let coverage = coverage_for_exact_impact_node(
            &impact.root,
            seed,
            index,
            graph,
            !complete_before,
            edge_rows_capped,
            &exclusion_provenance,
            &incoming_calls,
            &tested_by,
            &options,
            &mut budget,
        );
        impact_partial |= coverage.uncertainty.node_capped
            || coverage.uncertainty.depth_capped
            || coverage.uncertainty.edge_rows_capped;
        per_node.push(ImpactTestGapNodeResult {
            impact_node,
            identity,
            coverage: Some(coverage),
        });
    }
    let after_index = root_index_generation(conn, &impact.root)?
        .context("impact root disappeared after test query")?;
    let after_graph = root_graph_generation(conn, &impact.root)?
        .context("impact root disappeared after test query")?;
    ensure!(
        after_index == index && after_graph == graph,
        "code-map generation changed during impact test-gap query"
    );
    ensure!(
        CanonicalRepoRoot::discover(Path::new(&impact.root))? == canonical,
        "physical impact root changed during test-gap query"
    );
    let persisted_identity_after: Option<String> = conn
        .query_row(
            "SELECT root_identity FROM code_map_roots WHERE root = ?1",
            rusqlite::params![&impact.root],
            |row| row.get(0),
        )
        .optional()
        .context("read persisted physical impact root identity after query")?
        .flatten();
    ensure!(
        persisted_identity_after.as_deref() == Some(canonical.identity().as_str()),
        "physical impact root changed during test-gap query"
    );
    let complete_after = root_snapshot_complete(conn, &impact.root)?;
    let freshness_after = index_freshness_receipt(conn, &impact.root)?;
    ensure!(
        complete_after && !freshness_after.stale,
        "impact root became partial or stale during test-gap query"
    );
    ensure!(
        freshness_before.filesystem_fingerprint == freshness_after.filesystem_fingerprint,
        "impact root filesystem changed during test-gap query"
    );
    impact_partial |= budget.receipt.capped;
    Ok(ImpactTestGapResult {
        root: impact.root.clone(),
        index_generation: index,
        graph_generation: graph,
        impact_digest: impact.digest.clone(),
        input,
        outcome: ImpactTestGapOutcome::Complete,
        per_node,
        impact_partial,
        work_budget: budget.finish(),
        exclusion_provenance: Some(exclusion_provenance),
        no_observed_test_is_not_absence: true,
    })
}

#[cfg(test)]
pub(crate) fn impact_test_gap_work_budget(result: &ImpactTestGapResult) -> ImpactTestGapWorkBudget {
    result.work_budget.clone()
}

pub fn test_coverage_for(
    conn: &Connection,
    root: &str,
    seed: TestCoverageNode,
    options: TestCoverageOptions,
) -> Result<TestCoverageResult> {
    ensure!(
        options.max_nodes > 0 && options.max_nodes <= MAX_TEST_EDGE_ROWS,
        "test coverage max_nodes must be 1..={MAX_TEST_EDGE_ROWS}"
    );
    let index_generation = root_index_generation(conn, root)?.unwrap_or(-1);
    let graph_generation = root_graph_generation(conn, root)?.unwrap_or(-1);
    let truncated_at: Option<i64> = conn
        .query_row(
            "SELECT truncated_at FROM code_map_roots WHERE root = ?1",
            rusqlite::params![root],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    let (edges, edge_rows_capped, _) = super::persist::load_edges_for_root_bounded_with_text_limit(
        conn,
        root,
        MAX_TEST_EDGE_ROWS,
        MAX_TEST_EDGE_TEXT_BYTES,
    )?;
    let exclusion_provenance = super::persist::root_test_evidence_exclusion_summary_bounded(
        conn,
        root,
        MAX_TEST_EDGE_ROWS,
    )?;
    let mut uncertainty = TestCoverageUncertainty {
        stale_graph: index_generation < 0 || graph_generation != index_generation,
        partial_graph: truncated_at.is_some() || exclusion_provenance.capped,
        edge_rows_capped,
        ..Default::default()
    };
    let mut targets = BTreeMap::from([(seed.clone(), 0usize)]);
    let mut frontier = VecDeque::from([(seed.clone(), 0usize)]);
    while let Some((node, distance)) = frontier.pop_front() {
        let incoming: Vec<_> = edges
            .iter()
            .filter(|edge| edge.kind == EdgeKind::Calls && edge.to_name == node.symbol)
            .collect();
        if distance >= options.max_depth {
            if incoming.iter().any(|edge| {
                !targets.contains_key(&TestCoverageNode {
                    file: edge.from_file.clone(),
                    symbol: edge.from_symbol.clone(),
                })
            }) {
                uncertainty.depth_capped = true;
            }
            continue;
        }
        for edge in incoming {
            let caller = TestCoverageNode {
                file: edge.from_file.clone(),
                symbol: edge.from_symbol.clone(),
            };
            if targets.contains_key(&caller) {
                continue;
            }
            if targets.len() >= options.max_nodes {
                uncertainty.node_capped = true;
                break;
            }
            // Calls lack a resolved target-file identity, so a caller is a
            // traversal candidate but cannot certify that exact relationship.
            uncertainty.unresolved_or_ambiguous = true;
            targets.insert(caller.clone(), distance + 1);
            frontier.push_back((caller, distance + 1));
        }
    }
    let mut observed = BTreeSet::new();
    let mut result_text = 0usize;
    for (target, distance) in targets {
        let remaining = options
            .max_nodes
            .checked_sub(observed.len())
            .context("test result cap underflow")?;
        if remaining == 0 {
            uncertainty.node_capped = true;
            break;
        }
        let probe = remaining
            .checked_add(1)
            .context("test result probe overflow")?;
        let mut stmt = conn.prepare(
            "SELECT from_file, from_symbol, to_name, target_file, confidence, confidence_tier, \
             length(CAST(from_file AS BLOB)) + length(CAST(from_symbol AS BLOB)) + length(CAST(to_name AS BLOB)) + length(CAST(target_file AS BLOB)) \
             FROM code_map_edges WHERE root = ?1 AND kind = 'tested_by' AND target_file = ?2 AND to_name = ?3 \
             ORDER BY from_file, from_symbol LIMIT ?4",
        )?;
        let mut rows = stmt.query(rusqlite::params![
            root,
            &target.file,
            &target.symbol,
            i64::try_from(probe)?
        ])?;
        let mut seen = 0usize;
        while let Some(row) = rows.next()? {
            seen = seen
                .checked_add(1)
                .context("test result row count overflow")?;
            if seen > remaining {
                uncertainty.node_capped = true;
                break;
            }
            let bytes: i64 = row.get(6)?;
            let bytes = usize::try_from(bytes).context("invalid tested-by text size")?;
            result_text = result_text
                .checked_add(bytes)
                .context("test result text overflow")?;
            if result_text > MAX_TEST_RESULT_TEXT_BYTES {
                bail!(
                    "test coverage result exceeds bounded {MAX_TEST_RESULT_TEXT_BYTES}-byte text budget"
                );
            }
            let confidence: i64 = row.get(4)?;
            let tier: String = row.get(5)?;
            if confidence != i64::from(EdgeConfidenceTier::RESOLVED_CONFIDENCE)
                || tier != "resolved"
            {
                uncertainty.unresolved_or_ambiguous = true;
                continue;
            }
            observed.insert((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                distance,
            ));
        }
    }
    let observed_tests: Vec<_> = observed
        .into_iter()
        .map(|(file, symbol, name, target_file, distance)| ObservedTest {
            test: TestCoverageNode { file, symbol },
            target: TestCoverageNode {
                file: target_file,
                symbol: name,
            },
            confidence: EdgeConfidenceTier::RESOLVED_CONFIDENCE,
            confidence_tier: EdgeConfidenceTier::Resolved,
            provenance: TestCoverageProvenance::FrameworkAndConventionalPath,
            distance,
        })
        .collect();
    uncertainty.no_observed_test = observed_tests.is_empty();
    uncertainty.unsupported_or_unclassified = uncertainty.partial_graph
        || uncertainty.stale_graph
        || uncertainty.edge_rows_capped
        || uncertainty.node_capped
        || (uncertainty.no_observed_test
            && (uncertainty.unresolved_or_ambiguous
                || !exclusion_provenance.categories.is_empty()
                || exclusion_provenance.capped));
    Ok(TestCoverageResult {
        root: root.to_owned(),
        seed,
        index_generation,
        graph_generation,
        observed_tests,
        exclusion_provenance,
        uncertainty,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_map::persist::open;
    use tempfile::tempdir;

    fn root(conn: &Connection, name: &str, truncated_at: Option<i64>) {
        conn.execute(
            "INSERT INTO code_map_roots (root, scanned_at, total_files, total_bytes, total_loc, oversize_skipped, truncated_at, index_generation, graph_generation) VALUES (?1, 0, 0, 0, 0, 0, ?2, 4, 4)",
            rusqlite::params![name, truncated_at],
        ).unwrap();
    }

    fn tested_by(conn: &Connection, root: &str, test: &str) {
        conn.execute(
            "INSERT INTO code_map_edges (root, from_file, from_symbol, to_name, kind, confidence, confidence_tier, target_file) VALUES (?1, ?2, ?3, 'work', 'tested_by', 100, 'resolved', 'src/work.rs')",
            rusqlite::params![root, format!("tests/{test}.rs"), test],
        ).unwrap();
    }

    fn seed() -> TestCoverageNode {
        TestCoverageNode {
            file: "src/work.rs".into(),
            symbol: "work".into(),
        }
    }

    #[test]
    fn zero_observed_test_is_evidence_not_unsupported() {
        let dir = tempdir().unwrap();
        let conn = open(&dir.path().join("map.db")).unwrap();
        root(&conn, "/r", None);
        let result =
            test_coverage_for(&conn, "/r", seed(), TestCoverageOptions::default()).unwrap();
        assert!(result.uncertainty.no_observed_test);
        assert!(!result.uncertainty.unsupported_or_unclassified);
    }

    #[test]
    fn partial_root_and_result_probe_are_visible_and_root_scoped() {
        let dir = tempdir().unwrap();
        let conn = open(&dir.path().join("map.db")).unwrap();
        root(&conn, "/r", Some(12));
        root(&conn, "/other", None);
        tested_by(&conn, "/r", "one");
        tested_by(&conn, "/r", "two");
        tested_by(&conn, "/other", "foreign");
        let result = test_coverage_for(
            &conn,
            "/r",
            seed(),
            TestCoverageOptions {
                max_depth: 0,
                max_nodes: 1,
            },
        )
        .unwrap();
        assert!(result.uncertainty.partial_graph);
        assert!(result.uncertainty.node_capped);
        assert_eq!(result.observed_tests.len(), 1);
        assert_ne!(result.observed_tests[0].test.symbol, "foreign");
    }
}

// Append this complete cfg(test) module to src/code_map/test_coverage.rs.
// It deliberately uses real CRG-02 results, scanned temp roots, and the code-map
// SQLite service; no counter-only fixture is accepted as test-gap evidence.
#[cfg(test)]
mod impact_gap_behavior_tests {
    use super::*;
    use crate::code_map::graph::{CodeEdge, EdgeConfidenceTier, EdgeKind};
    use crate::code_map::impact::impact_radius_for_path;
    use crate::code_map::persist::{open, persist_edges};
    use crate::code_map::{
        CanonicalRepoRoot, ImpactDirection, ImpactOptions, ImpactSeed, RebuildOptions,
        rebuild_snapshot,
    };
    use rusqlite::Connection;
    use std::path::PathBuf;
    use tempfile::{TempDir, tempdir};

    struct IndexedFixture {
        _repo_parent: TempDir,
        _db_parent: TempDir,
        repo: PathBuf,
        db: PathBuf,
        conn: Connection,
        root: String,
    }

    fn indexed_fixture(files: &[(&str, &str)]) -> IndexedFixture {
        let repo_parent = tempdir().expect("fixture repository parent");
        let repo = repo_parent.path().join("repo");
        std::fs::create_dir_all(&repo).expect("fixture repository");
        for (relative, source) in files {
            let path = repo.join(relative);
            std::fs::create_dir_all(path.parent().expect("fixture parent"))
                .expect("fixture source parent");
            std::fs::write(path, source).expect("fixture source");
        }
        let root = CanonicalRepoRoot::discover(&repo).expect("canonical fixture root");
        let db_parent = tempdir().expect("fixture database parent");
        let db = db_parent.path().join("code_map.db");
        rebuild_snapshot(&root, &db, RebuildOptions::default())
            .expect("publish complete native code-map snapshot");
        let conn = open(&db).expect("open published code-map SQLite");
        IndexedFixture {
            _repo_parent: repo_parent,
            _db_parent: db_parent,
            repo,
            db,
            conn,
            root: root.display().to_owned(),
        }
    }

    fn primary_sources() -> [(&'static str, &'static str); 4] {
        [
            ("src/work.rs", "pub fn work() { wrapper(); }\n"),
            ("src/wrapper.rs", "pub fn wrapper() { work(); }\n"),
            ("src/other.rs", "pub fn other() {}\n"),
            (
                "tests/work_tests.rs",
                "#[test]\nfn observes_work() { work(); }\n#[test]\nfn observes_other() { other(); }\n",
            ),
        ]
    }

    fn fanout_sources() -> [(&'static str, &'static str); 4] {
        [
            ("src/work.rs", "pub fn work() {}\n"),
            ("src/other.rs", "pub fn other() {}\n"),
            ("src/wrapper.rs", "pub fn wrapper() { work(); other(); }\n"),
            (
                "tests/work_tests.rs",
                "#[test]\nfn observes_work() { work(); }\n#[test]\nfn observes_other() { other(); }\n",
            ),
        ]
    }

    fn wide_fanout_sources() -> [(&'static str, &'static str); 7] {
        [
            ("src/one.rs", "pub fn one() {}\n"),
            ("src/two.rs", "pub fn two() {}\n"),
            ("src/three.rs", "pub fn three() {}\n"),
            ("src/four.rs", "pub fn four() {}\n"),
            ("src/five.rs", "pub fn five() {}\n"),
            (
                "src/wrapper.rs",
                "pub fn wrapper() { one(); two(); three(); four(); five(); }\n",
            ),
            (
                "tests/fanout_tests.rs",
                "#[test]\nfn observes_one() { one(); }\n#[test]\nfn observes_two() { two(); }\n#[test]\nfn observes_three() { three(); }\n#[test]\nfn observes_four() { four(); }\n#[test]\nfn observes_five() { five(); }\n",
            ),
        ]
    }

    fn impact_from_wrapper(fixture: &IndexedFixture, max_nodes: usize) -> ImpactResult {
        impact_radius_for_path(
            &fixture.conn,
            &fixture.repo,
            &[ImpactSeed::symbol("src/wrapper.rs", "wrapper")],
            ImpactOptions {
                direction: ImpactDirection::Callees,
                max_depth: 8,
                max_nodes,
                allow_stale: false,
            },
        )
        .expect("real CRG-02 impact result")
    }

    fn coverage_for<'a>(result: &'a ImpactTestGapResult, symbol: &str) -> &'a TestCoverageResult {
        result
            .per_node
            .iter()
            .find(|node| node.impact_node.symbol == symbol)
            .and_then(|node| node.coverage.as_ref())
            .unwrap_or_else(|| panic!("expected coverage for {symbol}; got {:?}", result.per_node))
    }

    #[test]
    fn indexed_crg02_impact_observes_test_evidence_and_keeps_full_identity() {
        let fixture = indexed_fixture(&primary_sources());
        let impact = impact_from_wrapper(&fixture, 32);
        assert!(
            impact
                .impacted_nodes
                .iter()
                .any(|node| node.node.symbol == "work")
        );

        let gap = test_gap_for_impact(&fixture.conn, &impact, TestCoverageOptions::default())
            .expect("complete impact-gap receipt");
        assert_eq!(gap.outcome, ImpactTestGapOutcome::Complete);
        assert_eq!(gap.root, impact.root);
        assert_eq!(gap.impact_digest, impact.digest);
        assert_eq!(gap.input.source_index_generation, impact.index_generation);
        assert_eq!(gap.input.source_graph_generation, impact.graph_generation);
        assert!(!gap.impact_partial);
        assert!(gap.no_observed_test_is_not_absence);

        let work = coverage_for(&gap, "work");
        assert!(work.observed_tests.iter().any(|observed| {
            observed.test.file == "tests/work_tests.rs"
                && observed.test.symbol == "observes_work"
                && observed.target.file == "src/work.rs"
                && observed.target.symbol == "work"
                && observed.confidence_tier == EdgeConfidenceTier::Resolved
        }));
        let receipt_work = gap
            .per_node
            .iter()
            .find(|node| node.impact_node.symbol == "work")
            .expect("work impact identity receipt");
        let impact_work = impact
            .impacted_nodes
            .iter()
            .find(|node| node.node.symbol == "work")
            .expect("work CRG-02 identity");
        assert_eq!(receipt_work.impact_node, impact_work.node);
        assert_eq!(receipt_work.identity, ImpactTestGapIdentity::Exact);
    }

    #[test]
    fn impact_gap_projects_root_scoped_classifier_exclusions_without_inventing_edges() {
        let sources = [
            ("src/work.rs", "pub fn work() {}\n"),
            ("src/wrapper.rs", "pub fn wrapper() { work(); }\n"),
            ("src/left.rs", "pub fn duplicated() {}\n"),
            ("src/right.rs", "pub fn duplicated() {}\n"),
            (
                "tests/work_tests.rs",
                "#[test]\nfn observes_work() { work(); }\n",
            ),
            (
                "tests/helpers/support.rs",
                "#[test]\nfn ignored_helper() {}\n",
            ),
            (
                "tests/fixtures/case.rs",
                "#[test]\nfn ignored_fixture() {}\n",
            ),
            (
                "tests/generated/case.rs",
                "#[test]\nfn ignored_generated() {}\n",
            ),
            ("tests/foreign/case.go", "func TestForeign() {}\n"),
        ];
        let fixture = indexed_fixture(&sources);
        let impact = impact_from_wrapper(&fixture, 64);
        let gap = test_gap_for_impact(
            &fixture.conn,
            &impact,
            TestCoverageOptions {
                max_depth: 3,
                max_nodes: 64,
            },
        )
        .expect("root-scoped exclusion provenance");
        let exclusions = gap
            .exclusion_provenance
            .as_ref()
            .expect("complete input reads one aggregate from the same root generation");
        assert!(!exclusions.capped);
        assert_eq!(
            exclusions
                .categories
                .get(&super::super::graph::TestEvidenceExclusionCategory::HelperOrFixture),
            Some(&2)
        );
        assert_eq!(
            exclusions
                .categories
                .get(&super::super::graph::TestEvidenceExclusionCategory::Generated),
            Some(&1)
        );
        assert_eq!(
            exclusions
                .categories
                .get(&super::super::graph::TestEvidenceExclusionCategory::UnsupportedLanguage),
            Some(&1)
        );
        assert_eq!(
            exclusions
                .categories
                .get(&super::super::graph::TestEvidenceExclusionCategory::DuplicateTarget),
            Some(&1)
        );
        let work = coverage_for(&gap, "work");
        assert!(work.observed_tests.iter().any(|observed| {
            observed.test.file == "tests/work_tests.rs" && observed.test.symbol == "observes_work"
        }));
        assert!(
            work.uncertainty.unresolved_or_ambiguous,
            "the fixture retains its inferred call traversal without promoting it to an exact edge"
        );
        assert!(
            !work.uncertainty.unsupported_or_unclassified,
            "root-wide exclusions do not make an exact positive observation unknown"
        );
    }

    #[test]
    fn duplicate_file_symbol_with_distinct_line_and_kind_stays_two_truthful_nodes() {
        let fixture = indexed_fixture(&primary_sources());
        let mut impact = impact_from_wrapper(&fixture, 32);
        let original = impact
            .impacted_nodes
            .iter()
            .find(|node| node.node.symbol == "work")
            .expect("work impact identity")
            .clone();
        let mut distinct = original.clone();
        distinct.node.line = distinct.node.line.saturating_add(100);
        distinct.node.kind = "method".into();
        impact.impacted_nodes.push(distinct.clone());

        let gap = test_gap_for_impact(&fixture.conn, &impact, TestCoverageOptions::default())
            .expect("identity-safe impact-gap receipt");
        let duplicate_receipts: Vec<_> = gap
            .per_node
            .iter()
            .filter(|node| {
                node.impact_node.file == original.node.file && node.impact_node.symbol == "work"
            })
            .collect();
        assert_eq!(
            duplicate_receipts.len(),
            2,
            "do not collapse concrete CRG-02 identities to file+symbol"
        );
        assert!(
            duplicate_receipts
                .iter()
                .any(|node| node.impact_node == original.node)
        );
        assert!(
            duplicate_receipts
                .iter()
                .any(|node| node.impact_node == distinct.node)
        );
        assert!(
            duplicate_receipts.iter().all(|node| {
                node.identity == ImpactTestGapIdentity::UnresolvedOrAmbiguous
                    && node.coverage.is_none()
            }),
            "line/kind ambiguity must remain explicit rather than borrowing another declaration's evidence"
        );
    }

    #[test]
    fn stale_and_each_crg02_cap_provenance_return_typed_empty_receipts() {
        let fixture = indexed_fixture(&primary_sources());
        std::fs::write(
            fixture.repo.join("src/work.rs"),
            "pub fn changed_after_index() {}\n",
        )
        .expect("make the indexed root stale");
        let stale = impact_radius_for_path(
            &fixture.conn,
            &fixture.repo,
            &[ImpactSeed::symbol("src/wrapper.rs", "wrapper")],
            ImpactOptions {
                allow_stale: true,
                ..ImpactOptions::default()
            },
        )
        .expect("CRG-02 returns a stale-marked result only under explicit opt-in");
        let stale_gap = test_gap_for_impact(&fixture.conn, &stale, TestCoverageOptions::default())
            .expect("typed stale rejection receipt");
        assert!(stale_gap.input.stale);
        assert_eq!(
            stale_gap.outcome,
            ImpactTestGapOutcome::RejectedInput(ImpactTestGapRejection::Stale)
        );
        assert!(stale_gap.per_node.is_empty());
        assert!(
            stale_gap.exclusion_provenance.is_none(),
            "rejected stale input must not borrow exclusion facts from any persisted root"
        );

        let fresh = indexed_fixture(&fanout_sources());
        let truncated = impact_from_wrapper(&fresh, 1);
        assert!(
            truncated.truncated,
            "one CRG-02 node cannot represent both cycle neighbors"
        );
        let truncated_gap =
            test_gap_for_impact(&fresh.conn, &truncated, TestCoverageOptions::default())
                .expect("typed traversal-cap rejection receipt");
        assert!(truncated_gap.input.truncated);
        assert_eq!(
            truncated_gap.outcome,
            ImpactTestGapOutcome::RejectedInput(ImpactTestGapRejection::Truncated)
        );
        assert!(truncated_gap.per_node.is_empty());

        let capped_fixture = indexed_fixture(&primary_sources());
        let mut capped = impact_from_wrapper(&capped_fixture, 32);
        capped.budget_truncated = true;
        let capped_gap = test_gap_for_impact(
            &capped_fixture.conn,
            &capped,
            TestCoverageOptions::default(),
        )
        .expect("typed evidence-budget rejection receipt");
        assert!(capped_gap.input.budget_truncated);
        assert_eq!(
            capped_gap.outcome,
            ImpactTestGapOutcome::RejectedInput(ImpactTestGapRejection::BudgetTruncated)
        );
        assert!(capped_gap.per_node.is_empty());

        let evidence_fixture = indexed_fixture(&primary_sources());
        let mut evidence_capped = impact_from_wrapper(&evidence_fixture, 32);
        evidence_capped.evidence_truncated = true;
        let evidence_gap = test_gap_for_impact(
            &evidence_fixture.conn,
            &evidence_capped,
            TestCoverageOptions::default(),
        )
        .expect("typed evidence-cap rejection receipt");
        assert!(evidence_gap.input.evidence_truncated);
        assert_eq!(
            evidence_gap.outcome,
            ImpactTestGapOutcome::RejectedInput(ImpactTestGapRejection::EvidenceTruncated)
        );
        assert!(evidence_gap.per_node.is_empty());
    }

    #[test]
    fn wrong_root_and_physical_replacement_are_rejected_before_test_claims() {
        let fixture = indexed_fixture(&primary_sources());
        let mut wrong_root = impact_from_wrapper(&fixture, 32);
        let foreign = tempdir().expect("foreign root");
        std::fs::write(foreign.path().join("foreign.rs"), "pub fn foreign() {}\n")
            .expect("foreign source");
        let foreign_root =
            CanonicalRepoRoot::discover(foreign.path()).expect("canonical foreign root");
        rebuild_snapshot(&foreign_root, &fixture.db, RebuildOptions::default())
            .expect("index foreign root in same SQLite");
        wrong_root.root = foreign_root.display().to_owned();
        let wrong_root_error =
            test_gap_for_impact(&fixture.conn, &wrong_root, TestCoverageOptions::default())
                .expect_err("foreign-root certificate must not query primary impact nodes");
        assert!(
            wrong_root_error
                .to_string()
                .contains("crosses canonical root")
        );

        let replacement_fixture = indexed_fixture(&primary_sources());
        let impact = impact_from_wrapper(&replacement_fixture, 32);
        let moved = replacement_fixture.repo.with_file_name("original-moved");
        std::fs::rename(&replacement_fixture.repo, &moved).expect("move indexed physical root");
        std::fs::create_dir_all(&replacement_fixture.repo).expect("replacement root");
        for (relative, source) in primary_sources() {
            let path = replacement_fixture.repo.join(relative);
            std::fs::create_dir_all(path.parent().expect("replacement parent"))
                .expect("replacement parent create");
            std::fs::write(path, source).expect("same-content replacement source");
        }
        let replacement_result = test_gap_for_impact(
            &replacement_fixture.conn,
            &impact,
            TestCoverageOptions::default(),
        );
        std::fs::remove_dir_all(&replacement_fixture.repo).expect("remove physical replacement");
        std::fs::rename(&moved, &replacement_fixture.repo)
            .expect("restore original for temp cleanup");
        let replacement_error = replacement_result
            .expect_err("same-content physical replacement must still invalidate the bound root");
        assert!(
            replacement_error
                .to_string()
                .contains("physical impact root changed")
        );
    }

    #[test]
    fn cycle_depth_and_global_work_caps_are_visible_without_per_node_budget_reset() {
        let fixture = indexed_fixture(&primary_sources());
        let impact = impact_from_wrapper(&fixture, 32);
        let depth_gap = test_gap_for_impact(
            &fixture.conn,
            &impact,
            TestCoverageOptions {
                max_depth: 0,
                max_nodes: 32,
            },
        )
        .expect("depth-bounded impact-gap receipt");
        assert!(coverage_for(&depth_gap, "work").uncertainty.depth_capped);
        assert!(depth_gap.impact_partial);

        let fanout = indexed_fixture(&wide_fanout_sources());
        let fanout_impact = impact_from_wrapper(&fanout, 32);
        assert!(
            fanout_impact.impacted_nodes.len() >= 2,
            "fanout must yield multiple real CRG-02 nodes"
        );
        let globally_capped = test_gap_for_impact(
            &fanout.conn,
            &fanout_impact,
            TestCoverageOptions {
                max_depth: 8,
                max_nodes: 32,
            },
        )
        .expect("globally bounded impact-gap receipt");
        let work = impact_test_gap_work_budget(&globally_capped);
        assert_eq!(work.max_units, 32);
        assert!(
            work.capped,
            "cap must be recorded on the shared service receipt"
        );
        assert!(work.consumed_units <= work.max_units);
        assert_eq!(work.remaining_units + work.consumed_units, work.max_units);
        assert_eq!(
            work.root_edge_loads, 1,
            "root edges must be materialized once for the whole impact"
        );
        assert!(work.root_edges_loaded > 0);
        assert!(
            work.root_edge_rows_read <= work.max_units,
            "the SQLite edge read, including its sentinel, is charged to the shared budget"
        );
        assert!(work.traversal_nodes > 0);
        assert!(work.tested_by_probes > 0);
        assert!(globally_capped.impact_partial);
        assert!(
            globally_capped.per_node.len() < fanout_impact.impacted_nodes.len(),
            "one global work budget must stop before every real impact node; a per-node reset would cover the entire fanout"
        );
    }

    #[test]
    fn inferred_test_edge_is_truthful_unknown_not_proof_of_absence() {
        let mut fixture = indexed_fixture(&primary_sources());
        persist_edges(
            &mut fixture.conn,
            &fixture.root,
            &[
                CodeEdge::inferred_call("src/wrapper.rs", "wrapper", "work"),
                CodeEdge {
                    from_file: "tests/work_tests.rs".into(),
                    from_symbol: "observes_work".into(),
                    to_name: "work".into(),
                    target_file: Some("src/work.rs".into()),
                    kind: EdgeKind::TestedBy,
                    confidence: EdgeConfidenceTier::INFERRED_CONFIDENCE,
                    confidence_tier: EdgeConfidenceTier::Inferred,
                },
            ],
        )
        .expect("publish actual unresolved tested-by evidence");
        let impact = impact_from_wrapper(&fixture, 32);
        let gap = test_gap_for_impact(&fixture.conn, &impact, TestCoverageOptions::default())
            .expect("unsupported-evidence receipt");
        let work = coverage_for(&gap, "work");
        assert!(work.observed_tests.is_empty());
        assert!(work.uncertainty.no_observed_test);
        assert!(work.uncertainty.unresolved_or_ambiguous);
        assert!(work.uncertainty.unsupported_or_unclassified);
        assert!(gap.no_observed_test_is_not_absence);
    }
}
