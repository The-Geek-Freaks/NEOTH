//! W166 source contract: plan custody, current importer mapping, and registry
//! support are distinct claims and must drift together only through review.

use std::collections::BTreeMap;

use neoth_openclaw_custody::{
    pinned_inventory::{pinned_inventory_fixture_json, pinned_inventory_upstream_evidence_json},
    CHANNEL_ALIASES,
};
use neothd::channels::registry::CHANNEL_REGISTRY;
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    rows: Vec<FixtureRow>,
}

#[derive(Deserialize)]
struct FixtureRow {
    canonical_id: String,
    planned_neoth_target: String,
    current_importer_target: Option<String>,
    current_registry_channel: Option<String>,
    evidence: FixtureEvidence,
}

#[derive(Deserialize)]
struct FixtureEvidence {
    upstream_path: String,
    upstream_sha256: String,
    upstream_bytes: u64,
}

#[derive(Deserialize)]
struct UpstreamEvidenceRow {
    path: String,
    sha256: String,
    bytes: u64,
    status: u16,
}

#[test]
fn pinned_inventory_keeps_plan_current_importer_registry_and_evidence_claims_distinct() {
    let fixture: Fixture = serde_json::from_str(pinned_inventory_fixture_json()).unwrap();
    let upstream: Vec<UpstreamEvidenceRow> =
        serde_json::from_str(pinned_inventory_upstream_evidence_json()).unwrap();
    let upstream_by_path = upstream
        .iter()
        .map(|row| (row.path.as_str(), row))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(fixture.rows.len(), 31);
    assert_eq!(upstream_by_path.len(), 31);

    let current_rows = fixture
        .rows
        .iter()
        .filter(|row| row.current_importer_target.is_some())
        .collect::<Vec<_>>();
    assert_eq!(current_rows.len(), CHANNEL_ALIASES.len());

    for row in &fixture.rows {
        let upstream_row = upstream_by_path
            .get(row.evidence.upstream_path.as_str())
            .expect("every fixture evidence record must have an upstream witness");
        assert_eq!(upstream_row.status, 200);
        assert_eq!(upstream_row.sha256, row.evidence.upstream_sha256);
        assert_eq!(upstream_row.bytes, row.evidence.upstream_bytes);

        match (&row.current_importer_target, &row.current_registry_channel) {
            (Some(importer_target), Some(registry_channel)) => {
                assert_eq!(
                    CHANNEL_ALIASES
                        .iter()
                        .find_map(|(source, target)| (*source == row.canonical_id.as_str()).then_some(*target)),
                    Some(importer_target.as_str())
                );
                assert_eq!(row.planned_neoth_target.as_str(), importer_target.as_str());

                let descriptor = CHANNEL_REGISTRY
                    .iter()
                    .find(|descriptor| descriptor.id.as_str() == registry_channel.as_str())
                    .expect("current registry binding must name a production channel");
                assert!(
                    descriptor.id.as_str() == row.canonical_id.as_str()
                        || descriptor
                            .migration_aliases
                            .iter()
                            .any(|alias| *alias == row.canonical_id.as_str()),
                    "registry binding must accept the OpenClaw canonical source"
                );
            }
            (None, None) => {
                // Planned targets are intentionally not runtime claims.
            }
            _ => panic!("current importer and registry bindings must be paired"),
        }
    }

    for (source, target) in CHANNEL_ALIASES {
        assert!(fixture.rows.iter().any(|row| {
            row.canonical_id.as_str() == *source
                && row.current_importer_target.as_deref() == Some(*target)
                && row.current_registry_channel.is_some()
        }));
    }
}
