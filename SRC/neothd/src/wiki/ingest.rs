//! GOLD-FEAT-03 slice 2 — push self-wiki pages into ground-truth.
//!
//! Makes the rendered design corpus discoverable via recall: one short,
//! recall-friendly POINTER statement per doc (not the doc body — ground-truth
//! stays lean) is inserted into `idx_groundtruth` under the
//! [`WIKI_SCOPE`]. Re-ingest is idempotent: prior active self-wiki rows are
//! revoked first, so a rebuild never accretes duplicates.

use anyhow::Result;
use rusqlite::Connection;

use crate::memory::groundtruth::{Source, insert, list_for_scope, revoke};
use crate::wiki::sources::WikiSource;

/// Scope tag carried by every self-wiki ground-truth row — segregates the
/// corpus pointers from operator facts so they can be re-ingested as a unit.
pub const WIKI_SCOPE: &str = "neoth-self-wiki";

/// Counters returned by [`ingest_sources`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IngestStats {
    /// Fresh statements inserted this pass.
    pub inserted: usize,
    /// Prior active self-wiki rows revoked before re-inserting.
    pub revoked: usize,
}

/// The recall-friendly pointer statement for one doc: names the doc + links to
/// its Obsidian page, but carries no body text.
pub fn statement_for(source: &WikiSource) -> String {
    format!(
        "NEOTH {} design doc: {} — self-wiki page [[{}]] (source: {})",
        source.category.tag(),
        source.title,
        source.slug,
        source.rel_path
    )
}

/// Revoke the prior active self-wiki rows, then insert one fresh statement per
/// source. `now_ns` is injected so the asserted/revoked timestamps are
/// deterministic in tests.
pub fn ingest_sources(
    conn: &Connection,
    sources: &[WikiSource],
    now_ns: i64,
) -> Result<IngestStats> {
    let mut stats = IngestStats::default();
    for gt in list_for_scope(conn, WIKI_SCOPE)? {
        if gt.revoked_at.is_none() {
            revoke(conn, gt.id, now_ns)?;
            stats.revoked += 1;
        }
    }
    for src in sources {
        insert(
            conn,
            &statement_for(src),
            &Source::BulkText,
            WIKI_SCOPE,
            now_ns,
        )?;
        stats.inserted += 1;
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wiki::sources::SourceCategory;
    use std::path::PathBuf;

    fn src(slug: &str, title: &str, cat: SourceCategory) -> WikiSource {
        WikiSource {
            title: title.to_string(),
            slug: slug.to_string(),
            rel_path: format!("{slug}.md"),
            abs_path: PathBuf::from(format!("/x/{slug}.md")),
            category: cat,
        }
    }

    fn conn() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let c = crate::memory::store::open(&dir.path().join("views.db")).unwrap();
        (dir, c)
    }

    #[test]
    fn statement_is_a_pointer_not_the_body() {
        let s = src("SPEC_x", "Spec X", SourceCategory::Spec);
        let st = statement_for(&s);
        assert!(st.contains("Spec X"));
        assert!(st.contains("[[SPEC_x]]"));
        assert!(st.contains("spec"));
        assert!(st.contains("SPEC_x.md"));
    }

    #[test]
    fn ingest_inserts_one_row_per_source() {
        let (_d, c) = conn();
        let sources = vec![
            src("SPEC_a", "Spec A", SourceCategory::Spec),
            src("00_DESIGN", "Design", SourceCategory::Design),
        ];
        let stats = ingest_sources(&c, &sources, 1_000).unwrap();
        assert_eq!(stats.inserted, 2);
        assert_eq!(stats.revoked, 0);
        let rows = list_for_scope(&c, WIKI_SCOPE).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].source, "bulk-text");
        assert!(rows.iter().all(|r| r.revoked_at.is_none()));
    }

    #[test]
    fn re_ingest_revokes_prior_and_stays_idempotent() {
        let (_d, c) = conn();
        let sources = vec![src("SPEC_a", "Spec A", SourceCategory::Spec)];
        ingest_sources(&c, &sources, 1_000).unwrap();
        // Second pass with a changed corpus: the old row is revoked, the new
        // set inserted — active count reflects only the latest build.
        let sources2 = vec![
            src("SPEC_a", "Spec A v2", SourceCategory::Spec),
            src("SPEC_b", "Spec B", SourceCategory::Spec),
        ];
        let stats = ingest_sources(&c, &sources2, 2_000).unwrap();
        assert_eq!(stats.revoked, 1, "prior active row revoked");
        assert_eq!(stats.inserted, 2);
        let active = list_for_scope(&c, WIKI_SCOPE).unwrap();
        assert_eq!(active.len(), 2, "only the latest build is active");
        assert!(active.iter().any(|r| r.statement.contains("Spec A v2")));
    }
}
