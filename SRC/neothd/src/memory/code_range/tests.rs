use super::*;
use crate::memory::{ctx, gc, migrations, store};
use rusqlite::{Connection, OptionalExtension};
use tempfile::tempdir;

fn request(label: &str, content: &str) -> ctx::IndexRequest {
    ctx::IndexRequest {
        label: label.into(),
        content: content.into(),
        file_path: Some(label.into()),
        content_type: "code".into(),
        source_category: Some("transient".into()),
        event_id: None,
        document_provenance: None,
    }
}

fn index(conn: &mut Connection, label: &str, content: &str) -> i64 {
    ctx::index_document(conn, &request(label, content))
        .unwrap()
        .source_id
}

fn count(conn: &Connection, table: &str, source_id: i64) -> i64 {
    assert!(matches!(table, "code_source_ranges" | "code_chunk_ranges"));
    conn.query_row(
        &format!("SELECT count(*) FROM {table} WHERE source_id=?1"),
        [source_id],
        |row| row.get(0),
    )
    .unwrap()
}

type Snapshot = Vec<(&'static str, Vec<Vec<rusqlite::types::Value>>)>;

fn snapshot(conn: &Connection) -> Snapshot {
    [
        "sources",
        "chunks",
        "chunks_trigram",
        "vocabulary",
        "logical_documents",
        "logical_document_events",
        "ctx_logical_state",
        "sqlite_sequence",
        "code_source_ranges",
        "code_chunk_ranges",
        "meta",
    ]
    .into_iter()
    .map(|table| {
        let mut stmt = conn
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .unwrap();
        let columns = stmt.column_count();
        let rows = stmt
            .query_map([], |row| {
                (0..columns)
                    .map(|i| row.get(i))
                    .collect::<rusqlite::Result<Vec<rusqlite::types::Value>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        (table, rows)
    })
    .collect()
}

#[test]
fn duplicate_code_chunks_keep_distinct_offsets_in_all_search_modes() {
    let dir = tempdir().unwrap();
    let mut conn = store::open(&dir.path().join("views.db")).unwrap();
    let token = "rangequartz";
    let block = format!("{token}{}", " ".repeat(4096 - token.len()));
    let content = block.repeat(2);
    let source_id = index(&mut conn, "duplicate.rs", &content);
    assert_eq!(count(&conn, "code_chunk_ranges", source_id), 4);
    for (query, mode) in [
        ("rangequartz", ctx::SearchMode::Bm25),
        ("gequartz", ctx::SearchMode::Trigram),
        ("rangequartzz", ctx::SearchMode::Fuzzy),
    ] {
        let hits = ctx::search(&conn, query, 10).unwrap();
        assert_eq!(hits.len(), 2, "{query}");
        let mut ranges = Vec::new();
        for hit in hits {
            assert_eq!(hit.mode, mode);
            assert_eq!(hit.content, block);
            let proof = hit.code_provenance.unwrap();
            assert_eq!(proof.source.text_sha256, sha256(content.as_bytes()));
            assert_eq!(proof.source.text_bytes, 8192);
            assert_eq!(proof.source.coverage, CodeRangeCoverage::Complete);
            let range = proof.range.unwrap();
            assert_eq!(range.sha256, sha256(block.as_bytes()));
            ranges.push((range.ordinal, range.start_byte, range.end_byte));
        }
        ranges.sort();
        assert_eq!(ranges, vec![(0, 0, 4096), (1, 4096, 8192)]);
    }
}

#[test]
fn code_ranges_preserve_unicode_crlf_and_whitespace_bytes() {
    let dir = tempdir().unwrap();
    let mut conn = store::open(&dir.path().join("views.db")).unwrap();
    let prefix = "  café\r\n";
    let content = format!(
        "{prefix}{}🦀 finquartz  \r\n",
        " ".repeat(4095 - prefix.len())
    );
    index(&mut conn, "unicode.rs", &content);
    let mut ranges = Vec::new();
    for query in ["café", "finquartz"] {
        let hits = ctx::search(&conn, query, 10).unwrap();
        assert_eq!(hits.len(), 1);
        let hit = &hits[0];
        let range = hit
            .code_provenance
            .as_ref()
            .unwrap()
            .range
            .as_ref()
            .unwrap();
        assert_eq!(
            content.get(range.start_byte as usize..range.end_byte as usize),
            Some(hit.content.as_str())
        );
        assert_eq!(range.sha256, sha256(hit.content.as_bytes()));
        ranges.push((range.start_byte, range.end_byte));
    }
    assert_eq!(ranges, vec![(0, 4095), (4095, content.len() as u64)]);
}

#[test]
fn code_ranges_retain_supplied_document_provenance_independently() {
    let dir = tempdir().unwrap();
    let mut conn = store::open(&dir.path().join("views.db")).unwrap();
    let mut req = request("provenance.rs", "fn provenancequartz() {}");
    let supplied = crate::memory::document_provenance::DocumentProvenance {
        schema: "neoth.document-provenance.v1".into(),
        parser_version: "document-extractor/v1".into(),
        source_bytes_sha256: "a".repeat(64),
        source_bytes: 100,
        extracted_text_sha256: sha256(req.content.as_bytes()),
        extracted_text_bytes: req.content.len() as u64,
        extracted_text_encoding: "utf-8".into(),
        extracted_text_truncated: true,
        structure: None,
    };
    req.document_provenance = Some(supplied.clone());
    ctx::index_document(&mut conn, &req).unwrap();
    let hits = ctx::search(&conn, "provenancequartz", 10).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].source_document_provenance, Some(supplied));
    assert_eq!(
        hits[0]
            .code_provenance
            .as_ref()
            .unwrap()
            .source
            .parser_version,
        CODE_RANGE_PARSER_VERSION
    );
}

#[test]
fn code_ranges_empty_and_limit_states_are_explicit_after_reopen() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("views.db");
    let mut conn = store::open(&path).unwrap();
    for (label, content) in [("empty.rs", ""), ("whitespace.rs", " \r\n\t ")] {
        let report = ctx::index_document(&mut conn, &request(label, content)).unwrap();
        let source = report.code_source_ranges.unwrap();
        assert_eq!(source.coverage, CodeRangeCoverage::OmittedEmpty);
        assert_eq!(source.text_bytes, content.len() as u64);
        assert_eq!(report.chunk_count, 0);
        assert_eq!(count(&conn, "code_chunk_ranges", report.source_id), 0);
    }
    // No automatic DocumentProvenance: preserve the existing >8 MiB code path.
    // Only the first chunk has tokens, keeping the actual boundary fixture bounded.
    for chunks in [MAX_MAPPED_CHUNKS, MAX_MAPPED_CHUNKS + 1] {
        let mut content = " ".repeat(chunks * 4096);
        content.replace_range(..14, "overflowquartz");
        let report = ctx::index_document(&mut conn, &request("limit.rs", &content)).unwrap();
        assert_eq!(report.chunk_count, chunks);
        assert_eq!(report.bytes, content.len());
        let expected = if chunks == MAX_MAPPED_CHUNKS {
            CodeRangeCoverage::Complete
        } else {
            CodeRangeCoverage::OmittedLimit
        };
        assert_eq!(
            report.code_source_ranges.as_ref().unwrap().coverage,
            expected
        );
        assert_eq!(
            count(&conn, "code_chunk_ranges", report.source_id),
            if expected == CodeRangeCoverage::Complete {
                (chunks * 2) as i64
            } else {
                0
            }
        );
        drop(conn);
        conn = store::open(&path).unwrap();
        let hits = ctx::search(&conn, "overflowquartz", 10).unwrap();
        assert_eq!(hits.len(), 1);
        let proof = hits[0].code_provenance.as_ref().unwrap();
        assert_eq!(proof.source.coverage, expected);
        assert_eq!(proof.source.text_sha256, sha256(content.as_bytes()));
        assert_eq!(
            proof.range.is_some(),
            expected == CodeRangeCoverage::Complete
        );
    }
}

#[test]
fn corrupt_or_missing_code_hit_mappings_are_errors_not_legacy() {
    for mutation in [
        "DELETE FROM code_chunk_ranges WHERE fts_table='chunks'",
        "UPDATE code_chunk_ranges SET chunk_sha256=printf('%064d',0) WHERE fts_table='chunks'",
        "UPDATE code_chunk_ranges SET end_byte=end_byte-1 WHERE fts_table='chunks'",
        "UPDATE code_chunk_ranges SET ordinal=1 WHERE fts_table='chunks'",
        "UPDATE code_source_ranges SET parser_version='unknown'",
        "UPDATE code_source_ranges SET text_sha256=upper(text_sha256)",
        "UPDATE sources SET chunk_count=chunk_count+1",
        "UPDATE code_source_ranges SET coverage='omitted_limit'",
    ] {
        let dir = tempdir().unwrap();
        let mut conn = store::open(&dir.path().join("views.db")).unwrap();
        index(&mut conn, "corrupt.rs", "fn corruptquartz() {}");
        conn.execute_batch(mutation).unwrap();
        assert!(
            ctx::search(&conn, "corruptquartz", 10).is_err(),
            "{mutation}"
        );
    }
}

#[test]
fn cross_source_code_mapping_is_rejected_before_returning_hits() {
    let dir = tempdir().unwrap();
    let mut conn = store::open(&dir.path().join("views.db")).unwrap();
    let first = index(&mut conn, "first.rs", "fn sharedquartz() {}");
    let second = index(&mut conn, "second.rs", "fn sharedquartz() {}");
    conn.execute(
        "DELETE FROM code_chunk_ranges WHERE source_id=?1 AND fts_table='chunks'",
        [second],
    )
    .unwrap();
    conn.execute(
        "UPDATE code_chunk_ranges SET source_id=?1 WHERE source_id=?2 AND fts_table='chunks'",
        params![second, first],
    )
    .unwrap();
    assert!(ctx::search(&conn, "sharedquartz", 10).is_err());
}

#[test]
fn code_range_replacement_removes_old_mappings() {
    let dir = tempdir().unwrap();
    let mut conn = store::open(&dir.path().join("views.db")).unwrap();
    let old = index(&mut conn, "replace.rs", "fn oldquartz() {}");
    let new = index(&mut conn, "replace.rs", "fn newzircon() {}");
    assert_ne!(old, new);
    assert_eq!(count(&conn, "code_source_ranges", old), 0);
    assert_eq!(count(&conn, "code_chunk_ranges", old), 0);
    assert_eq!(count(&conn, "code_source_ranges", new), 1);
    assert_eq!(count(&conn, "code_chunk_ranges", new), 2);
    assert!(
        ctx::search(&conn, "newzircon", 10).unwrap()[0]
            .code_provenance
            .is_some()
    );
    assert!(ctx::search(&conn, "oldquartz", 10).unwrap().is_empty());
}

#[test]
fn code_range_purge_modes_remove_mapping_rows() {
    for scope in [
        ctx::PurgeScope::Source("purge.rs"),
        ctx::PurgeScope::Category("transient"),
        ctx::PurgeScope::All,
    ] {
        let dir = tempdir().unwrap();
        let mut conn = store::open(&dir.path().join("views.db")).unwrap();
        let source = index(&mut conn, "purge.rs", "fn purgequartz() {}");
        assert_eq!(count(&conn, "code_chunk_ranges", source), 2);
        assert_eq!(ctx::purge(&mut conn, scope).unwrap(), 1);
        assert_eq!(count(&conn, "code_source_ranges", source), 0);
        assert_eq!(count(&conn, "code_chunk_ranges", source), 0);
    }
}

#[test]
fn code_range_gc_paths_remove_mapping_rows() {
    for ttl in [true, false] {
        let dir = tempdir().unwrap();
        let mut conn = store::open(&dir.path().join("views.db")).unwrap();
        let source = index(&mut conn, "gc.rs", "fn gcquartz() {}");
        conn.execute("UPDATE sources SET indexed_ts=0 WHERE id=?1", [source])
            .unwrap();
        assert_eq!(count(&conn, "code_chunk_ranges", source), 2);
        if ttl {
            assert_eq!(gc::run_pass(&mut conn, 100, 1).unwrap().sources_dropped, 1);
        } else {
            assert_eq!(gc::enforce_size_cap(&mut conn, 0).unwrap(), 1);
        }
        assert_eq!(count(&conn, "code_source_ranges", source), 0);
        assert_eq!(count(&conn, "code_chunk_ranges", source), 0);
    }
}

#[test]
fn code_range_mapping_insert_failure_rolls_back_replacement() {
    let dir = tempdir().unwrap();
    let mut conn = store::open(&dir.path().join("views.db")).unwrap();
    index(&mut conn, "atomic.rs", "fn oldquartz() {}");
    conn.execute_batch(
        "CREATE TRIGGER reject_second_code_mapping BEFORE INSERT ON code_chunk_ranges
         WHEN NEW.fts_table='chunks_trigram'
         BEGIN SELECT RAISE(ABORT,'injected mapping failure'); END;",
    )
    .unwrap();
    let before = snapshot(&conn);
    assert!(ctx::index_document(&mut conn, &request("atomic.rs", "fn newzircon() {}")).is_err());
    assert_eq!(snapshot(&conn), before);
    conn.execute_batch("DROP TRIGGER reject_second_code_mapping;")
        .unwrap();
    index(&mut conn, "atomic.rs", "fn newzircon() {}");
    assert_eq!(ctx::search(&conn, "newzircon", 10).unwrap().len(), 1);
}

#[test]
fn migration_from_51_keeps_legacy_hits_unknown_and_new_hits_mapped() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("views.db");
    let mut conn = store::open(&path).unwrap();
    index(&mut conn, "legacy.rs", "fn legacyquartz() {}");
    remove_schema_for_legacy_fixture(&conn).unwrap();
    conn.execute("UPDATE meta SET value='51' WHERE key='schema_version'", [])
        .unwrap();
    drop(conn);
    let mut conn = store::open(&path).unwrap();
    assert_eq!(
        migrations::current_version(&conn).unwrap(),
        store::SCHEMA_VERSION
    );
    let hits = ctx::search(&conn, "legacyquartz", 10).unwrap();
    assert_eq!(hits.len(), 1);
    assert!(hits[0].code_provenance.is_none());
    index(&mut conn, "new.rs", "fn newzircon() {}");
    assert!(
        ctx::search(&conn, "newzircon", 10).unwrap()[0]
            .code_provenance
            .is_some()
    );
}

#[test]
fn migration_from_51_rolls_back_tables_and_stamp_on_failure() {
    let dir = tempdir().unwrap();
    let mut conn = store::open(&dir.path().join("views.db")).unwrap();
    index(&mut conn, "legacy.rs", "fn legacyquartz() {}");
    remove_schema_for_legacy_fixture(&conn).unwrap();
    conn.execute_batch(
        "UPDATE meta SET value='51' WHERE key='schema_version';
         CREATE TRIGGER reject_schema_stamp BEFORE INSERT ON meta
         WHEN NEW.key='schema_version' AND NEW.value='52'
         BEGIN SELECT RAISE(ABORT,'injected schema stamp failure'); END;",
    )
    .unwrap();
    assert!(migrations::migrate(&mut conn, 51, 52).is_err());
    assert_eq!(migrations::current_version(&conn).unwrap(), 51);
    for table in ["code_source_ranges", "code_chunk_ranges"] {
        let exists: Option<String> = conn
            .query_row(
                "SELECT name FROM sqlite_master WHERE name=?1",
                [table],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        assert!(exists.is_none());
    }
    conn.execute_batch("DROP TRIGGER reject_schema_stamp;")
        .unwrap();
    migrations::migrate(&mut conn, 51, 52).unwrap();
    assert_eq!(migrations::current_version(&conn).unwrap(), 52);
    assert_eq!(ctx::search(&conn, "legacyquartz", 10).unwrap().len(), 1);
}

#[test]
fn migration_from_51_rejects_conflicting_range_objects() {
    for name in [
        "code_source_ranges",
        "code_chunk_ranges",
        "Code_Source_Ranges",
    ] {
        let dir = tempdir().unwrap();
        let mut conn = store::open(&dir.path().join("views.db")).unwrap();
        remove_schema_for_legacy_fixture(&conn).unwrap();
        conn.execute("UPDATE meta SET value='51' WHERE key='schema_version'", [])
            .unwrap();
        conn.execute_batch(&format!("CREATE VIEW {name} AS SELECT 17 AS retained;"))
            .unwrap();
        assert!(migrations::migrate(&mut conn, 51, 52).is_err());
        assert_eq!(migrations::current_version(&conn).unwrap(), 51);
        let retained: i64 = conn
            .query_row(&format!("SELECT retained FROM {name}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(retained, 17);
    }
}

#[test]
fn logical_code_ranges_follow_rename_revision_rollback_and_purge_owners() {
    use serde_json::json;

    let dir = tempdir().unwrap();
    let mut conn = store::open(&dir.path().join("views.db")).unwrap();
    let registration = json!({
        "action": "register", "logical_document_id": "code-document",
        "logical_event_id": "registered", "authorization_epoch": 0,
        "index": request("logical.rs", "fn logicalquartz() {}")
    });
    let first =
        ctx::logical::apply(&mut conn, &serde_json::to_vec(&registration).unwrap()).unwrap();
    let first_proof = ctx::search(&conn, "logicalquartz", 10).unwrap()[0]
        .code_provenance
        .clone()
        .unwrap();
    let peer = json!({
        "action": "register", "logical_document_id": "independent-document",
        "logical_event_id": "peer-registered", "authorization_epoch": 0,
        "index": request("independent.rs", "fn logicalquartz() {}")
    });
    let peer = ctx::logical::apply(&mut conn, &serde_json::to_vec(&peer).unwrap()).unwrap();
    assert_ne!(peer.source_id, first.source_id);
    assert_ne!(peer.logical_document_id, first.logical_document_id);
    let peer_proof = ctx::search(&conn, "logicalquartz", 10)
        .unwrap()
        .into_iter()
        .find(|hit| hit.source_id == peer.source_id)
        .unwrap()
        .code_provenance
        .unwrap();
    assert_eq!(peer_proof.source.text_sha256, first_proof.source.text_sha256);

    let rename = json!({
        "action": "metadata_rename", "logical_document_id": "code-document",
        "logical_event_id": "renamed", "authorization_epoch": 0,
        "expected": {
            "source_id": first.source_id, "content_revision_id": first.content_revision_id,
            "current_event_id": first.current_event_id
        },
        "new_label": "renamed.rs", "new_file_path": "moved/renamed.rs"
    });
    let renamed = ctx::logical::apply(&mut conn, &serde_json::to_vec(&rename).unwrap()).unwrap();
    assert_eq!(renamed.source_id, first.source_id);
    assert_eq!(renamed.content_revision_id, first.content_revision_id);
    let renamed_hit = ctx::search(&conn, "logicalquartz", 10)
        .unwrap()
        .into_iter()
        .find(|hit| hit.source_id == first.source_id)
        .unwrap();
    assert_eq!(renamed_hit.label, "renamed.rs");
    assert_eq!(renamed_hit.file_path.as_deref(), Some("moved/renamed.rs"));
    assert_eq!(renamed_hit.code_provenance, Some(first_proof));

    let revision = json!({
        "action": "revise", "logical_document_id": "code-document",
        "logical_event_id": "revised", "authorization_epoch": 0,
        "expected": {
            "source_id": renamed.source_id, "content_revision_id": renamed.content_revision_id,
            "current_event_id": renamed.current_event_id
        },
        "index": request("renamed.rs", "fn revisedzircon() {}")
    });
    conn.execute_batch(
        "CREATE TRIGGER reject_logical_mapping BEFORE INSERT ON code_chunk_ranges
         WHEN NEW.fts_table='chunks_trigram'
         BEGIN SELECT RAISE(ABORT,'injected logical mapping failure'); END;",
    )
    .unwrap();
    let before = snapshot(&conn);
    assert!(ctx::logical::apply(&mut conn, &serde_json::to_vec(&revision).unwrap()).is_err());
    assert_eq!(snapshot(&conn), before);
    conn.execute_batch("DROP TRIGGER reject_logical_mapping;")
        .unwrap();
    let revised = ctx::logical::apply(&mut conn, &serde_json::to_vec(&revision).unwrap()).unwrap();
    assert_ne!(revised.source_id, first.source_id);
    assert_eq!(count(&conn, "code_chunk_ranges", first.source_id), 0);
    assert_eq!(count(&conn, "code_chunk_ranges", revised.source_id), 2);
    assert_eq!(count(&conn, "code_chunk_ranges", peer.source_id), 2);
    assert!(
        ctx::search(&conn, "revisedzircon", 10).unwrap()[0]
            .code_provenance
            .is_some()
    );
    assert_eq!(
        ctx::purge(&mut conn, ctx::PurgeScope::Category("transient")).unwrap(),
        2
    );
    assert_eq!(count(&conn, "code_chunk_ranges", revised.source_id), 0);
    assert_eq!(count(&conn, "code_chunk_ranges", peer.source_id), 0);
    assert!(ctx::logical::apply(&mut conn, &serde_json::to_vec(&registration).unwrap()).is_err());
}
