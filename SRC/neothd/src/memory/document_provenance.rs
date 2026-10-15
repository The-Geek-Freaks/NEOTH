//! Bounded provenance of extracted source text persisted by the ctx index.
//! Source hashes are extractor assertions, not document identity or trust.

use std::io;

use anyhow::{Result, bail};
use rusqlite::{Row, types::Type};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const DOCUMENT_PROVENANCE_SCHEMA: &str = "neoth.document-provenance.v1";
pub const DOCUMENT_PROVENANCE_ENCODING: &str = "utf-8";

const MAX_PARSER_VERSION_BYTES: usize = 64;
const MAX_DOCUMENT_SOURCE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DOCUMENT_TEXT_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DocumentProvenance {
    pub schema: String,
    pub parser_version: String,
    pub source_bytes_sha256: String,
    pub source_bytes: u64,
    pub extracted_text_sha256: String,
    pub extracted_text_bytes: u64,
    pub extracted_text_encoding: String,
    pub extracted_text_truncated: bool,
}

impl DocumentProvenance {
    /// Raw input bytes are not retained here. Their digest remains an
    /// extractor assertion; indexing verifies only the full extracted text.
    pub fn validate_metadata(&self) -> Result<()> {
        if self.schema != DOCUMENT_PROVENANCE_SCHEMA {
            bail!("unsupported document provenance schema");
        }
        if self.extracted_text_encoding != DOCUMENT_PROVENANCE_ENCODING {
            bail!("unsupported document provenance text encoding");
        }
        if self.parser_version.is_empty()
            || self.parser_version.len() > MAX_PARSER_VERSION_BYTES
            || !self
                .parser_version
                .bytes()
                .all(|byte| matches!(byte, b' '..=b'~'))
        {
            bail!("invalid document provenance parser version");
        }
        validate_lower_sha256(&self.source_bytes_sha256)?;
        validate_lower_sha256(&self.extracted_text_sha256)?;
        if self.source_bytes > MAX_DOCUMENT_SOURCE_BYTES {
            bail!("document provenance source byte count exceeds limit");
        }
        if self.extracted_text_bytes > MAX_DOCUMENT_TEXT_BYTES {
            bail!("document provenance extracted text byte count exceeds limit");
        }
        i64::try_from(self.source_bytes)?;
        i64::try_from(self.extracted_text_bytes)?;
        Ok(())
    }

    pub fn validate_for_content(&self, content: &str) -> Result<()> {
        self.validate_metadata()?;
        if self.extracted_text_bytes != u64::try_from(content.len())? {
            bail!("document provenance extracted text byte count does not match indexed content");
        }
        if self.extracted_text_sha256 != sha256_lower(content.as_bytes()) {
            bail!("document provenance extracted text digest does not match indexed content");
        }
        Ok(())
    }

    /// Other extractors remain unbound. A document extractor must provide the
    /// entire supported contract, without unknown nested fields.
    pub fn from_extraction_metadata(metadata: &Value) -> Result<Option<Self>> {
        let Some(metadata) = metadata.as_object() else {
            return Ok(None);
        };
        if metadata.get("extractor").and_then(Value::as_str) != Some("document") {
            return Ok(None);
        }
        let extracted_text_truncated = metadata
            .get("truncated")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow::anyhow!("invalid document provenance truncation flag"))?;
        let provenance = required_object(metadata, "provenance")?;
        require_exact_keys(
            provenance,
            &["schema", "parser_version", "source", "extracted_text"],
        )?;
        let source = required_object(provenance, "source")?;
        require_exact_keys(source, &["sha256", "bytes"])?;
        let text = required_object(provenance, "extracted_text")?;
        require_exact_keys(text, &["sha256", "bytes", "encoding"])?;
        let provenance = Self {
            schema: required_string(provenance, "schema")?.to_owned(),
            parser_version: required_string(provenance, "parser_version")?.to_owned(),
            source_bytes_sha256: required_string(source, "sha256")?.to_owned(),
            source_bytes: required_u64(source, "bytes")?,
            extracted_text_sha256: required_string(text, "sha256")?.to_owned(),
            extracted_text_bytes: required_u64(text, "bytes")?,
            extracted_text_encoding: required_string(text, "encoding")?.to_owned(),
            extracted_text_truncated,
        };
        provenance.validate_metadata()?;
        Ok(Some(provenance))
    }

    /// Column order: schema, parser, source hash, source bytes, text hash,
    /// text bytes, encoding, truncated. All NULL means unbound legacy data;
    /// partial NULL and malformed complete rows are integrity errors.
    pub fn from_row(row: &Row<'_>, start: usize) -> rusqlite::Result<Option<Self>> {
        let schema: Option<String> = row.get(start)?;
        let parser: Option<String> = row.get(start + 1)?;
        let source_hash: Option<String> = row.get(start + 2)?;
        let source_bytes: Option<i64> = row.get(start + 3)?;
        let text_hash: Option<String> = row.get(start + 4)?;
        let text_bytes: Option<i64> = row.get(start + 5)?;
        let encoding: Option<String> = row.get(start + 6)?;
        let truncated: Option<i64> = row.get(start + 7)?;
        match (
            schema,
            parser,
            source_hash,
            source_bytes,
            text_hash,
            text_bytes,
            encoding,
            truncated,
        ) {
            (None, None, None, None, None, None, None, None) => Ok(None),
            (
                Some(schema),
                Some(parser_version),
                Some(source_bytes_sha256),
                Some(source_bytes),
                Some(extracted_text_sha256),
                Some(text_bytes),
                Some(extracted_text_encoding),
                Some(truncated),
            ) => {
                let source_bytes =
                    u64::try_from(source_bytes).map_err(|_| persisted_error(start + 3))?;
                let extracted_text_bytes =
                    u64::try_from(text_bytes).map_err(|_| persisted_error(start + 5))?;
                let extracted_text_truncated = match truncated {
                    0 => false,
                    1 => true,
                    _ => return Err(persisted_error(start + 7)),
                };
                let provenance = Self {
                    schema,
                    parser_version,
                    source_bytes_sha256,
                    source_bytes,
                    extracted_text_sha256,
                    extracted_text_bytes,
                    extracted_text_encoding,
                    extracted_text_truncated,
                };
                provenance
                    .validate_metadata()
                    .map_err(|_| persisted_error(start))?;
                Ok(Some(provenance))
            }
            _ => Err(persisted_error(start)),
        }
    }
}

fn sha256_lower(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn validate_lower_sha256(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("invalid document provenance SHA-256 digest");
    }
    Ok(())
}

fn required_object<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Map<String, Value>> {
    object
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("invalid document provenance metadata"))
}

fn required_string<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("invalid document provenance metadata"))
}

fn required_u64(object: &Map<String, Value>, key: &str) -> Result<u64> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("invalid document provenance metadata"))
}

fn require_exact_keys(object: &Map<String, Value>, expected: &[&str]) -> Result<()> {
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        bail!("invalid document provenance metadata shape");
    }
    Ok(())
}

fn persisted_error(column: usize) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        Type::Text,
        Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid persisted document provenance",
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document_metadata() -> Value {
        serde_json::json!({
            "extractor": "document", "format": "rtf", "truncated": false,
            "provenance": {
                "schema": DOCUMENT_PROVENANCE_SCHEMA,
                "parser_version": "document-extractor/v1",
                "source": {"sha256": "a".repeat(64), "bytes": 12},
                "extracted_text": {
                    "sha256": sha256_lower("über".as_bytes()),
                    "bytes": "über".len(), "encoding": DOCUMENT_PROVENANCE_ENCODING
                }
            }
        })
    }

    #[test]
    fn document_metadata_binds_exact_utf8_text() {
        let provenance = DocumentProvenance::from_extraction_metadata(&document_metadata())
            .unwrap()
            .unwrap();
        provenance.validate_for_content("über").unwrap();
        assert_eq!(provenance.source_bytes, 12);
        assert_eq!(provenance.extracted_text_bytes, 5);
        assert!(!provenance.extracted_text_truncated);
        let mut wrong_hash = provenance.clone();
        wrong_hash.extracted_text_sha256 = "b".repeat(64);
        assert!(wrong_hash.validate_for_content("über").is_err());
        let mut wrong_size = provenance;
        wrong_size.extracted_text_bytes = 4;
        assert!(wrong_size.validate_for_content("über").is_err());
    }

    #[test]
    fn document_metadata_rejects_malformed_shapes_and_unbounded_values() {
        let valid = document_metadata();
        let cases = [
            ("/provenance", Value::Null),
            ("/truncated", Value::String("false".into())),
            ("/provenance/source/sha256", Value::String("A".repeat(64))),
            (
                "/provenance/source/bytes",
                Value::from(MAX_DOCUMENT_SOURCE_BYTES + 1),
            ),
            (
                "/provenance/extracted_text/bytes",
                Value::from(MAX_DOCUMENT_TEXT_BYTES + 1),
            ),
            ("/provenance/extracted_text/bytes", Value::from(-1)),
            ("/provenance/parser_version", Value::String("x".repeat(65))),
            (
                "/provenance/parser_version",
                Value::String("bad\nversion".into()),
            ),
            ("/provenance/schema", Value::String("future".into())),
            (
                "/provenance/extracted_text/encoding",
                Value::String("latin-1".into()),
            ),
        ];
        for (path, value) in cases {
            let mut bad = valid.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(
                DocumentProvenance::from_extraction_metadata(&bad).is_err(),
                "{path}"
            );
        }
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove("provenance");
        assert!(DocumentProvenance::from_extraction_metadata(&missing).is_err());
        let mut extra = valid;
        extra["provenance"]["source"]["unbound"] = Value::Bool(true);
        assert!(DocumentProvenance::from_extraction_metadata(&extra).is_err());
    }

    #[test]
    fn other_extractors_and_legacy_metadata_remain_unbound() {
        for metadata in [
            Value::Null,
            serde_json::json!({}),
            serde_json::json!({"extractor": "pdf"}),
        ] {
            assert_eq!(
                DocumentProvenance::from_extraction_metadata(&metadata).unwrap(),
                None
            );
        }
    }
}
