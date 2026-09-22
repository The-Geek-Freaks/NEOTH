//! Pinned, lossless OpenClaw channel inventory custody.
//!
//! The importer deliberately handles only manifest-backed channel keys. This
//! fixture retains the wider pinned 31-row ledger, including special and
//! quarantined public surfaces plus the synthetic QA-only row, so omissions
//! cannot be mistaken for unsupported or implemented adapters.

use anyhow::{Context as _, Result, ensure};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

use crate::{AUDITED_OPENCLAW_SCHEMA_COMMIT, CHANNEL_ALIASES, KNOWN_CHANNEL_KEYS, sha256_bytes};

const FIXTURE: &str = include_str!("fixtures/pinned_channel_inventory_v1.json");
const FIXTURE_SHA256: &str = "54e9966a4508b8259bb6a05f88dd53daa9b827754b6b96fe0bda4bb516b753e9";
const UPSTREAM_EVIDENCE: &str = include_str!("fixtures/openclaw_upstream_evidence_v1.json");
const UPSTREAM_EVIDENCE_SHA256: &str =
    "a38299e9e80de3fa3dbd31db8093aaa211172cadb50333746855589e25d7800b";
const FIXTURE_NAME: &str = "openclaw-pinned-channel-inventory-v1";
const OPENCLAW_REPOSITORY: &str = "openclaw/openclaw";
const PRIMARY_LEDGER: &str = "plans/001-openclaw-channel-migration-parity.md";
const LEDGER_ROWS: usize = 31;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedChannelInventorySummary {
    pub ledger_rows: usize,
    pub public_rows: usize,
    pub clickclack_official_rows: usize,
    pub qa_test_only_rows: usize,
    pub manifest_backed_rows: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryFixture {
    schema_version: u32,
    fixture_name: String,
    source: FixtureSource,
    rows: Vec<InventoryRow>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureSource {
    repository: String,
    commit: String,
    primary_ledger: String,
    ledger_rows: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryRow {
    row_id: usize,
    canonical_id: String,
    openclaw_aliases: Vec<String>,
    role: InventoryRole,
    disposition: InventoryDisposition,
    /// Plan-only target; it does not assert a currently available adapter.
    planned_neoth_target: String,
    /// Actual current importer target, if CHANNEL_ALIASES maps this source.
    current_importer_target: Option<String>,
    /// Registry channel corresponding to the current importer mapping, if any.
    current_registry_channel: Option<String>,
    manifest_backed: bool,
    evidence: UpstreamEvidence,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum InventoryRole {
    Public,
    ClickclackOfficial,
    QaTestOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum InventoryDisposition {
    Upgrade,
    Adopt,
    Special,
    QuarantinedExternal,
    EvidenceSkip,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamEvidence {
    upstream_path: String,
    upstream_sha256: String,
    upstream_bytes: u64,
}

/// Parse and validate the bundled 31-row OpenClaw inventory against the
/// importer’s existing manifest-backed key contract.
/// Package-owned fixture bytes for repository integration contracts.
pub fn pinned_inventory_fixture_json() -> &'static str {
    FIXTURE
}

/// Package-owned pinned upstream evidence manifest for repository contracts.
pub fn pinned_inventory_upstream_evidence_json() -> &'static str {
    UPSTREAM_EVIDENCE
}
pub fn validate_pinned_channel_inventory() -> Result<PinnedChannelInventorySummary> {
    ensure!(
        sha256_bytes(FIXTURE.as_bytes()) == FIXTURE_SHA256,
        "pinned OpenClaw channel inventory fixture digest drifted"
    );
    ensure!(
        sha256_bytes(UPSTREAM_EVIDENCE.as_bytes()) == UPSTREAM_EVIDENCE_SHA256,
        "pinned OpenClaw upstream evidence manifest digest drifted"
    );
    validate_fixture(FIXTURE, KNOWN_CHANNEL_KEYS)
}

fn validate_fixture(
    fixture: &str,
    known_channel_keys: &[&str],
) -> Result<PinnedChannelInventorySummary> {
    let inventory: InventoryFixture = serde_json::from_str(fixture)
        .context("pinned OpenClaw channel inventory fixture is invalid JSON")?;
    ensure!(
        inventory.schema_version == 1,
        "unsupported pinned inventory schema version"
    );
    ensure!(
        inventory.fixture_name == FIXTURE_NAME,
        "unexpected pinned inventory fixture name"
    );
    ensure!(
        inventory.source.repository == OPENCLAW_REPOSITORY,
        "unexpected pinned inventory repository"
    );
    ensure!(
        inventory.source.commit == AUDITED_OPENCLAW_SCHEMA_COMMIT,
        "pinned inventory commit differs from audited custody contract"
    );
    ensure!(
        inventory.source.primary_ledger == PRIMARY_LEDGER,
        "unexpected pinned inventory primary ledger"
    );
    ensure!(
        inventory.source.ledger_rows == LEDGER_ROWS,
        "pinned inventory source ledger count drifted"
    );
    ensure!(
        inventory.rows.len() == LEDGER_ROWS,
        "pinned inventory must contain exactly {LEDGER_ROWS} rows"
    );

    let mut row_ids = BTreeSet::new();
    let mut canonical_ids = BTreeSet::new();
    let mut all_names = BTreeSet::new();
    let mut manifest_keys = Vec::new();
    let mut public_rows = 0;
    let mut clickclack_rows = 0;
    let mut qa_rows = 0;
    let importer_aliases = CHANNEL_ALIASES.iter().copied().collect::<BTreeMap<_, _>>();

    for (offset, row) in inventory.rows.iter().enumerate() {
        ensure!(
            row.row_id == offset + 1,
            "pinned inventory row IDs must be contiguous and ledger ordered"
        );
        ensure!(
            row_ids.insert(row.row_id),
            "duplicate pinned inventory row ID {}",
            row.row_id
        );
        ensure!(
            !row.canonical_id.is_empty(),
            "pinned inventory canonical ID is empty"
        );
        ensure!(
            canonical_ids.insert(row.canonical_id.as_str()),
            "duplicate pinned inventory canonical ID {}",
            row.canonical_id
        );
        ensure!(
            all_names.insert(row.canonical_id.as_str()),
            "pinned inventory canonical/alias collision for {}",
            row.canonical_id
        );
        for alias in &row.openclaw_aliases {
            ensure!(!alias.is_empty(), "pinned inventory alias is empty");
            ensure!(
                all_names.insert(alias.as_str()),
                "duplicate or canonical-colliding pinned inventory alias {alias}"
            );
        }
        validate_evidence(&row.evidence)?;
        match importer_aliases.get(row.canonical_id.as_str()) {
            Some(expected) => {
                ensure!(
                    row.current_importer_target.as_deref() == Some(*expected),
                    "current importer target drift for {}",
                    row.canonical_id
                );
                ensure!(
                    row.planned_neoth_target == *expected,
                    "current importer target must agree with planned target for {}",
                    row.canonical_id
                );
            }
            None => ensure!(
                row.current_importer_target.is_none(),
                "row {} claims a current importer target without a CHANNEL_ALIASES binding",
                row.canonical_id
            ),
        }
        ensure!(
            row.current_importer_target.is_some() == row.current_registry_channel.is_some(),
            "row {} must pair current importer and registry bindings",
            row.canonical_id
        );

        if row.manifest_backed {
            manifest_keys.push(row.canonical_id.as_str());
        }

        match row.role {
            InventoryRole::Public => {
                public_rows += 1;
                ensure!(
                    row.disposition != InventoryDisposition::EvidenceSkip,
                    "public inventory row {} cannot be evidence-skip",
                    row.canonical_id
                );
            }
            InventoryRole::ClickclackOfficial => {
                clickclack_rows += 1;
                ensure!(
                    row.canonical_id == "clickclack",
                    "only clickclack may have the official special role"
                );
                ensure!(
                    row.manifest_backed,
                    "clickclack must remain manifest-backed"
                );
                ensure!(
                    row.disposition == InventoryDisposition::Adopt,
                    "clickclack must remain an adoption row"
                );
                ensure!(
                    !row.planned_neoth_target.is_empty(),
                    "clickclack must remain targetable"
                );
            }
            InventoryRole::QaTestOnly => {
                qa_rows += 1;
                ensure!(
                    row.canonical_id == "qa-channel",
                    "only qa-channel may have the test-only role"
                );
                ensure!(
                    row.manifest_backed,
                    "qa-channel must remain manifest-backed for deterministic importer coverage"
                );
                ensure!(
                    row.disposition == InventoryDisposition::EvidenceSkip,
                    "qa-channel must remain evidence-skip"
                );
                ensure!(
                    row.planned_neoth_target.is_empty(),
                    "qa-channel must never be targetable"
                );
            }
        }

        if row.disposition == InventoryDisposition::QuarantinedExternal {
            ensure!(
                !row.manifest_backed,
                "quarantined external row {} cannot be manifest-backed",
                row.canonical_id
            );
            ensure!(
                row.planned_neoth_target.is_empty(),
                "quarantined external row {} cannot be targetable",
                row.canonical_id
            );
        }
    }

    ensure!(
        public_rows == 29,
        "pinned inventory must retain 29 public rows"
    );
    ensure!(
        clickclack_rows == 1,
        "pinned inventory must retain one official clickclack row"
    );
    ensure!(qa_rows == 1, "pinned inventory must retain one QA-only row");
    ensure!(
        manifest_keys.len() == 26,
        "pinned inventory must retain 26 manifest-backed rows"
    );

    let fixture_manifest = manifest_keys.into_iter().collect::<BTreeSet<_>>();
    let importer_manifest = known_channel_keys.iter().copied().collect::<BTreeSet<_>>();
    ensure!(
        importer_manifest.len() == known_channel_keys.len(),
        "KNOWN_CHANNEL_KEYS contains duplicate keys"
    );
    ensure!(
        fixture_manifest == importer_manifest,
        "KNOWN_CHANNEL_KEYS must exactly match the fixture manifest-backed key set"
    );

    Ok(PinnedChannelInventorySummary {
        ledger_rows: inventory.rows.len(),
        public_rows,
        clickclack_official_rows: clickclack_rows,
        qa_test_only_rows: qa_rows,
        manifest_backed_rows: known_channel_keys.len(),
    })
}

fn validate_evidence(evidence: &UpstreamEvidence) -> Result<()> {
    ensure!(
        !evidence.upstream_path.is_empty(),
        "pinned inventory evidence path is empty"
    );
    ensure!(
        evidence.upstream_bytes > 0,
        "pinned inventory evidence byte count must be positive"
    );
    ensure!(
        evidence.upstream_sha256.len() == 64
            && evidence
                .upstream_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "pinned inventory evidence SHA-256 must be lower-case hexadecimal"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn changed_fixture(change: impl FnOnce(&mut Value)) -> String {
        let mut fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        change(&mut fixture);
        serde_json::to_string(&fixture).unwrap()
    }

    #[test]
    fn bundled_fixture_matches_importer_manifest_contract() {
        assert_eq!(
            validate_pinned_channel_inventory().unwrap(),
            PinnedChannelInventorySummary {
                ledger_rows: 31,
                public_rows: 29,
                clickclack_official_rows: 1,
                qa_test_only_rows: 1,
                manifest_backed_rows: 26,
            }
        );
    }

    #[test]
    fn rejects_clickclack_test_only_or_excluded_classification() {
        let fixture = changed_fixture(|fixture| {
            let row = &mut fixture["rows"][29];
            row["role"] = Value::String("qa_test_only".to_owned());
        });
        assert!(validate_fixture(&fixture, KNOWN_CHANNEL_KEYS).is_err());
    }

    #[test]
    fn rejects_targetable_or_public_qa_channel() {
        let fixture = changed_fixture(|fixture| {
            let row = &mut fixture["rows"][30];
            row["planned_neoth_target"] = Value::String("qa".to_owned());
        });
        assert!(validate_fixture(&fixture, KNOWN_CHANNEL_KEYS).is_err());
    }

    #[test]
    fn rejects_unmapped_current_importer_or_registry_claim() {
        let importer_claim = changed_fixture(|fixture| {
            fixture["rows"][1]["current_importer_target"] = Value::String("feishu".to_owned());
            fixture["rows"][1]["current_registry_channel"] = Value::String("feishu".to_owned());
        });
        assert!(validate_fixture(&importer_claim, KNOWN_CHANNEL_KEYS).is_err());

        let unpaired_registry = changed_fixture(|fixture| {
            fixture["rows"][1]["current_registry_channel"] = Value::String("feishu".to_owned());
        });
        assert!(validate_fixture(&unpaired_registry, KNOWN_CHANNEL_KEYS).is_err());
    }

    #[test]
    fn rejects_manifest_key_drift() {
        let mut drifted = KNOWN_CHANNEL_KEYS.to_vec();
        drifted[0] = "missing-channel";
        assert!(validate_fixture(FIXTURE, &drifted).is_err());
    }

    #[test]
    fn rejects_alias_canonical_collision() {
        let fixture = changed_fixture(|fixture| {
            fixture["rows"][0]["openclaw_aliases"] = serde_json::json!(["feishu"]);
        });
        assert!(validate_fixture(&fixture, KNOWN_CHANNEL_KEYS).is_err());
    }

    #[test]
    fn rejects_bad_evidence_hash_or_unpinned_source_commit() {
        let bad_hash = changed_fixture(|fixture| {
            fixture["rows"][0]["evidence"]["upstream_sha256"] = Value::String("ABC".to_owned());
        });
        assert!(validate_fixture(&bad_hash, KNOWN_CHANNEL_KEYS).is_err());

        let bad_commit = changed_fixture(|fixture| {
            fixture["source"]["commit"] = Value::String("deadbeef".to_owned());
        });
        assert!(validate_fixture(&bad_commit, KNOWN_CHANNEL_KEYS).is_err());
    }
}
