//! Source contracts for GOLD-LF-P1-08 stages 1–2 only.
//!
//! These assertions intentionally prove the absence of premature runtime
//! authority as well as the reserved schema/WAL surface.

#[test]
fn provenance_prerequisite_is_modern_sealed_and_not_a_producer() {
    let provenance = include_str!("../src/memory/transcript_mining_provenance.rs");
    let memory_mod = include_str!("../src/memory/mod.rs");
    let events = include_str!("../src/wal/events.rs");

    assert!(memory_mod.contains("pub(crate) mod transcript_mining_provenance;"));
    assert!(provenance.contains("struct AuthenticatedMiningSubject(Sha256Digest);"));
    assert!(provenance.contains("#[serde(deny_unknown_fields)]"));
    assert!(provenance.contains("TranscriptMiningBoundV1"));
    assert!(provenance.contains("TranscriptMiningRevokedV1"));
    assert!(provenance.contains("MAX_TRANSCRIPT_MINING_PAYLOAD_BYTES"));
    assert!(events.contains("TranscriptMiningBound = 0x28"));
    assert!(events.contains("TranscriptMiningRevoked = 0x29"));

    for premature_authority in [
        "pub(crate) fn append",
        "pub(crate) fn produce",
        "pub(crate) fn activate",
        "pub(crate) fn mine",
    ] {
        assert!(
            !provenance.contains(premature_authority),
            "stage 1-2 must not expose runtime authority: {premature_authority}",
        );
    }
}

#[test]
fn migration_contract_keeps_legacy_unbound_and_raw_text_out_of_provenance() {
    let migration = include_str!("../src/memory/migrations/mod.rs");
    let store = include_str!("../src/memory/store.rs");

    assert!(migration.contains("from: 35,"));
    assert!(migration.contains("to: 36,"));
    assert!(migration.contains("fn migration_v35_to_v36"));
    assert!(migration.contains("CREATE TABLE IF NOT EXISTS transcript_mining_provenance"));
    assert!(migration.contains("transcript_mining_raw_turn_deleted"));
    assert!(migration.contains("WHERE raw_turn_id = OLD.id AND lifecycle IN ('pending', 'active')"));
    assert!(store.contains("pub const SCHEMA_VERSION: i64 = 36;"));
    assert!(store.contains("CREATE TABLE IF NOT EXISTS transcript_mining_wal_outbox"));
    assert!(store.contains("raw_text_sha256 BLOB NOT NULL"));
    assert!(!store.contains("transcript_mining_provenance (\n            provenance_id          TEXT PRIMARY KEY NOT NULL\n                CHECK(length(provenance_id) BETWEEN 1 AND 64),\n            raw_turn_id            INTEGER NOT NULL CHECK(raw_turn_id > 0),\n            text"));
}
