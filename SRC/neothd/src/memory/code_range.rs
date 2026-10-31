//! Exact byte ranges for explicitly indexed code. Coordinates describe the
//! submitted UTF-8 snapshot, not original-file offsets or logical identity.

use anyhow::{Context, Result, ensure};
use rusqlite::{Row, Transaction, params, types::Type};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CODE_RANGE_PARSER_VERSION: &str = "ctx-code-utf8/1";
pub const MAX_MAPPED_CHUNKS: usize = 4096;

pub(crate) const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS code_source_ranges (
    source_id INTEGER PRIMARY KEY REFERENCES sources(id) ON DELETE CASCADE,
    parser_version TEXT NOT NULL,
    text_sha256 TEXT NOT NULL CHECK(length(text_sha256)=64),
    text_bytes INTEGER NOT NULL CHECK(text_bytes>=0),
    chunk_count INTEGER NOT NULL CHECK(chunk_count>=0),
    coverage TEXT NOT NULL CHECK(coverage IN ('complete','omitted_limit','omitted_empty'))
);
CREATE TABLE IF NOT EXISTS code_chunk_ranges (
    fts_table TEXT NOT NULL CHECK(fts_table IN ('chunks','chunks_trigram')),
    chunk_rowid INTEGER NOT NULL,
    source_id INTEGER NOT NULL REFERENCES code_source_ranges(source_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK(ordinal>=0),
    start_byte INTEGER NOT NULL CHECK(start_byte>=0),
    end_byte INTEGER NOT NULL CHECK(end_byte>start_byte),
    chunk_sha256 TEXT NOT NULL CHECK(length(chunk_sha256)=64),
    PRIMARY KEY(fts_table,chunk_rowid),
    UNIQUE(source_id,fts_table,ordinal)
);
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeRangeCoverage {
    Complete,
    OmittedLimit,
    OmittedEmpty,
}

impl CodeRangeCoverage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::OmittedLimit => "omitted_limit",
            Self::OmittedEmpty => "omitted_empty",
        }
    }
}

/// A digest assertion recorded when indexing the complete submitted text.
/// Reading a hit verifies its chunk digest, not the unavailable full snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeSourceRanges {
    pub parser_version: String,
    pub text_sha256: String,
    pub text_bytes: u64,
    pub chunk_count: u64,
    pub coverage: CodeRangeCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeChunkRange {
    pub ordinal: u64,
    /// Inclusive UTF-8 byte offset in the submitted indexed text.
    pub start_byte: u64,
    /// Exclusive UTF-8 byte offset in the submitted indexed text.
    pub end_byte: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeSearchProvenance {
    pub source: CodeSourceRanges,
    /// None is explicit when range coverage was omitted at the limit.
    pub range: Option<CodeChunkRange>,
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl CodeSourceRanges {
    fn new(content: &str, chunk_count: usize) -> Result<Self> {
        let coverage = if chunk_count == 0 {
            ensure!(content.trim().is_empty(), "nonempty code has no chunks");
            CodeRangeCoverage::OmittedEmpty
        } else if chunk_count > MAX_MAPPED_CHUNKS {
            CodeRangeCoverage::OmittedLimit
        } else {
            CodeRangeCoverage::Complete
        };
        let value = Self {
            parser_version: CODE_RANGE_PARSER_VERSION.into(),
            text_sha256: sha256(content.as_bytes()),
            text_bytes: u64::try_from(content.len())?,
            chunk_count: u64::try_from(chunk_count)?,
            coverage,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.parser_version == CODE_RANGE_PARSER_VERSION,
            "unknown code range parser"
        );
        ensure!(
            valid_digest(&self.text_sha256),
            "invalid code snapshot digest"
        );
        i64::try_from(self.text_bytes)?;
        i64::try_from(self.chunk_count)?;
        ensure!(
            self.chunk_count <= self.text_bytes,
            "code chunk count exceeds text bytes"
        );
        match self.coverage {
            CodeRangeCoverage::Complete => {
                ensure!(
                    self.chunk_count > 0 && self.chunk_count <= MAX_MAPPED_CHUNKS as u64,
                    "invalid complete code range coverage"
                );
            }
            CodeRangeCoverage::OmittedLimit => {
                ensure!(
                    self.chunk_count > MAX_MAPPED_CHUNKS as u64,
                    "invalid code range overflow"
                );
            }
            CodeRangeCoverage::OmittedEmpty => {
                ensure!(self.chunk_count == 0, "invalid empty code range coverage");
            }
        }
        Ok(())
    }
}

pub(crate) fn insert_source(
    tx: &Transaction<'_>,
    source_id: i64,
    content: &str,
    chunk_count: usize,
) -> Result<CodeSourceRanges> {
    let value = CodeSourceRanges::new(content, chunk_count)?;
    tx.execute(
        "INSERT INTO code_source_ranges
         (source_id,parser_version,text_sha256,text_bytes,chunk_count,coverage)
         VALUES (?1,?2,?3,?4,?5,?6)",
        params![
            source_id,
            value.parser_version,
            value.text_sha256,
            i64::try_from(value.text_bytes)?,
            i64::try_from(value.chunk_count)?,
            value.coverage.as_str()
        ],
    )?;
    Ok(value)
}

/// The caller checked the full source slice before invoking this function.
pub(crate) fn chunk_range(
    source: &CodeSourceRanges,
    ordinal: usize,
    start: usize,
    body: &str,
) -> Result<Option<CodeChunkRange>> {
    if source.coverage != CodeRangeCoverage::Complete {
        return Ok(None);
    }
    let range = CodeChunkRange {
        ordinal: u64::try_from(ordinal)?,
        start_byte: u64::try_from(start)?,
        end_byte: u64::try_from(
            start
                .checked_add(body.len())
                .context("code range overflow")?,
        )?,
        sha256: sha256(body.as_bytes()),
    };
    validate_range(source, &range, body)?;
    Ok(Some(range))
}

fn validate_range(source: &CodeSourceRanges, range: &CodeChunkRange, body: &str) -> Result<()> {
    ensure!(
        range.ordinal < source.chunk_count,
        "code range ordinal exceeds source"
    );
    ensure!(
        range.start_byte < range.end_byte && range.end_byte <= source.text_bytes,
        "code range exceeds snapshot"
    );
    ensure!(
        range.end_byte - range.start_byte == u64::try_from(body.len())?,
        "code range length does not match hit"
    );
    ensure!(
        valid_digest(&range.sha256) && range.sha256 == sha256(body.as_bytes()),
        "code range digest does not match hit"
    );
    if range.ordinal == 0 {
        ensure!(
            range.start_byte == 0,
            "first code range does not start at zero"
        );
    }
    if range.ordinal + 1 == source.chunk_count {
        ensure!(
            range.end_byte == source.text_bytes,
            "last code range does not end at snapshot"
        );
    }
    Ok(())
}

pub(crate) fn insert_chunk(
    tx: &Transaction<'_>,
    source_id: i64,
    table: &str,
    rowid: i64,
    range: &CodeChunkRange,
) -> Result<()> {
    tx.execute(
        "INSERT INTO code_chunk_ranges
         (fts_table,chunk_rowid,source_id,ordinal,start_byte,end_byte,chunk_sha256)
         VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![
            table,
            rowid,
            source_id,
            i64::try_from(range.ordinal)?,
            i64::try_from(range.start_byte)?,
            i64::try_from(range.end_byte)?,
            range.sha256
        ],
    )?;
    Ok(())
}

/// Called before the index transaction commits: mapping is all-or-none in both
/// FTS tables. Indexing beyond the mapping limit deliberately retains no ranges.
pub(crate) fn validate_inserted(
    tx: &Transaction<'_>,
    source_id: i64,
    source: &CodeSourceRanges,
) -> Result<()> {
    let expected = if source.coverage == CodeRangeCoverage::Complete {
        i64::try_from(source.chunk_count)?
    } else {
        0
    };
    for table in ["chunks", "chunks_trigram"] {
        let count: i64 = tx.query_row(
            "SELECT count(*) FROM code_chunk_ranges WHERE source_id=?1 AND fts_table=?2",
            params![source_id, table],
            |row| row.get(0),
        )?;
        ensure!(count == expected, "incomplete code range mapping");
    }
    Ok(())
}

/// Column order is owned by ctx::run_match. Joining by table and rowid (without
/// filtering source_id) makes stale or cross-source mappings fail visibly.
pub(crate) fn from_row(
    row: &Row<'_>,
    offset: usize,
    body: &str,
) -> rusqlite::Result<Option<CodeSearchProvenance>> {
    let decode = || -> Result<Option<CodeSearchProvenance>> {
        let snapshot_id: Option<i64> = row.get(offset)?;
        let mapping_id: Option<i64> = row.get(offset + 6)?;
        let Some(snapshot_id) = snapshot_id else {
            ensure!(mapping_id.is_none(), "code mapping has no source snapshot");
            return Ok(None);
        };
        let hit_id: i64 = row.get(0)?;
        let hit_type: String = row.get(4)?;
        let source_type: String = row.get(offset + 11)?;
        let source_chunks: i64 = row.get(offset + 12)?;
        ensure!(
            snapshot_id == hit_id && hit_type == "code" && source_type == "code",
            "code range source does not match hit"
        );
        let coverage: String = row.get(offset + 5)?;
        let coverage = match coverage.as_str() {
            "complete" => CodeRangeCoverage::Complete,
            "omitted_limit" => CodeRangeCoverage::OmittedLimit,
            "omitted_empty" => CodeRangeCoverage::OmittedEmpty,
            _ => anyhow::bail!("unknown code range coverage"),
        };
        let source = CodeSourceRanges {
            parser_version: row.get(offset + 1)?,
            text_sha256: row.get(offset + 2)?,
            text_bytes: u64::try_from(row.get::<_, i64>(offset + 3)?)?,
            chunk_count: u64::try_from(row.get::<_, i64>(offset + 4)?)?,
            coverage,
        };
        source.validate()?;
        ensure!(
            source.chunk_count == u64::try_from(source_chunks)?,
            "code source chunk count changed"
        );
        let range = if coverage == CodeRangeCoverage::Complete {
            ensure!(
                mapping_id == Some(hit_id),
                "missing or mismatched code hit range"
            );
            let range = CodeChunkRange {
                ordinal: u64::try_from(row.get::<_, i64>(offset + 7)?)?,
                start_byte: u64::try_from(row.get::<_, i64>(offset + 8)?)?,
                end_byte: u64::try_from(row.get::<_, i64>(offset + 9)?)?,
                sha256: row.get(offset + 10)?,
            };
            validate_range(&source, &range, body)?;
            Some(range)
        } else {
            ensure!(
                coverage == CodeRangeCoverage::OmittedLimit && mapping_id.is_none(),
                "omitted code ranges unexpectedly produced a mapped hit"
            );
            None
        };
        Ok(Some(CodeSearchProvenance { source, range }))
    };
    decode().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            offset,
            Type::Text,
            Box::new(std::io::Error::other(error.to_string())),
        )
    })
}

#[cfg(test)]
pub(crate) fn remove_schema_for_legacy_fixture(conn: &rusqlite::Connection) -> Result<()> {
    // These fixtures model v51 or earlier, including full reopen/migration.
    // Remove later schema objects as well; a lowered stamp alone is not a
    // historical database and must fail the migration collision guard.
    conn.execute_batch(
        "DROP TABLE IF EXISTS idx_email_seen_scoped; \
         DROP TABLE IF EXISTS code_chunk_ranges; DROP TABLE IF EXISTS code_source_ranges;",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests;
