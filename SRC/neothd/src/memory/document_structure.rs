//! Validated source-level DOCX ranges. These remain extractor assertions:
//! the index has neither the original ZIP member nor a chunk-to-XML mapping.
#[path = "document_numbering.rs"]
mod numbering;
use numbering::{NumberingProperties, decode_numbering_properties};
use std::io::{self, Write};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

pub(crate) const MAX_STRUCTURE_JSON_BYTES: usize = 256 * 1024;
const MAX_MEMBER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SCAN_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentStructure {
    schema: String,
    parser_version: String,
    scope: String,
    coordinate_system: String,
    entry: String,
    source_document: SourceDocument,
    entry_sha256: String,
    entry_bytes: u64,
    complete: bool,
    scan_complete: bool,
    omitted_tables_observed: usize,
    omissions_limited: bool,
    tables: Vec<Table>,
    omissions: Vec<Omission>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "decode_section_properties"
    )]
    section_properties: Option<SectionProperties>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "decode_numbering_properties"
    )]
    numbering_properties: Option<NumberingProperties>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceDocument {
    sha256: String,
    bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Table {
    source_range: [u64; 2],
    rows: Vec<Row>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Row {
    source_range: [u64; 2],
    cells: Vec<Cell>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Cell {
    source_range: [u64; 2],
    paragraph_source_ranges: Vec<[u64; 2]>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Omission {
    scope: String,
    reason: String,
    source_range: [u64; 2],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SectionProperties {
    complete: bool,
    omitted_observed: usize,
    omissions_limited: bool,
    ranges: Vec<SectionRange>,
    omissions: Vec<SectionOmission>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SectionRange {
    context: String,
    source_range: [u64; 2],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SectionOmission {
    reason: String,
    source_range: [u64; 2],
}

// Missing v1 field stays absent; an explicit null is never a supported contract.
fn decode_section_properties<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<SectionProperties>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    SectionProperties::deserialize(deserializer).map(Some)
}

impl SectionProperties {
    fn validate(&self, entry_bytes: u64, scan_complete: bool) -> Result<()> {
        ensure!(
            self.ranges.len() <= 256
                && self.omissions.len() <= 64
                && self.omitted_observed <= 200_000,
            "section property limit exceeded"
        );
        ensure!(
            self.complete
                == (scan_complete
                    && self.omitted_observed == 0
                    && self.omissions.is_empty()
                    && !self.omissions_limited),
            "inconsistent section completeness"
        );
        let mut previous_end = 0;
        for range in &self.ranges {
            ensure!(
                matches!(range.context.as_str(), "body" | "paragraph_properties"),
                "unsupported section property context"
            );
            ordered_range(range.source_range, [0, entry_bytes], &mut previous_end)?;
        }
        let mut omissions_end = 0;
        let mut detailed_omissions = 0;
        for omission in &self.omissions {
            ensure!(
                !omission.reason.is_empty()
                    && omission.reason.len() <= 64
                    && omission
                        .reason
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b == b'_'),
                "invalid section omission code"
            );
            if omission.reason == "metadata_limit" {
                ensure!(
                    omission.source_range == [0, entry_bytes] && self.ranges.is_empty(),
                    "invalid section metadata omission"
                );
            } else {
                ordered_range(omission.source_range, [0, entry_bytes], &mut omissions_end)?;
                ensure!(
                    self.ranges
                        .iter()
                        .all(|range| omission.source_range[1] <= range.source_range[0]
                            || omission.source_range[0] >= range.source_range[1]),
                    "omitted section overlaps emitted section"
                );
                detailed_omissions += 1;
            }
        }
        ensure!(
            detailed_omissions <= self.omitted_observed,
            "section omission counter understates recorded omissions"
        );
        Ok(())
    }
}

/// Bounds serialization before allocating an arbitrarily large JSON buffer.
struct BoundedJson(Vec<u8>);

impl Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_STRUCTURE_JSON_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::other(
                "document structure exceeds JSON byte limit",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bounded_json(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut writer = BoundedJson(Vec::new());
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.0)
}

impl DocumentStructure {
    pub(crate) fn from_value(value: &serde_json::Value) -> Result<Self> {
        Self::from_json_bytes(&bounded_json(value)?)
    }

    pub(crate) fn from_json_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_STRUCTURE_JSON_BYTES,
            "document structure exceeds JSON byte limit"
        );
        let structure: Self = serde_json::from_slice(bytes)?;
        structure.validate()?;
        Ok(structure)
    }

    pub(crate) fn to_json(&self) -> Result<String> {
        self.validate()?;
        Ok(String::from_utf8(bounded_json(self)?)?)
    }

    pub(crate) fn validate_against(&self, source_sha256: &str, source_bytes: u64) -> Result<()> {
        self.validate()?;
        ensure!(
            self.source_document.sha256 == source_sha256
                && self.source_document.bytes == source_bytes,
            "document structure is bound to another source"
        );
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        let v1 = self.schema == "neoth.document-structure.v1"
            && self.parser_version == "docx-table-ranges/v1"
            && self.scope == "physical-table-source-ranges"
            && self.section_properties.is_none()
            && self.numbering_properties.is_none();
        let v2 = self.schema == "neoth.document-structure.v2"
            && self.parser_version == "docx-table-section-properties/v2"
            && self.scope == "physical-table-and-section-property-source-ranges"
            && self.section_properties.is_some()
            && self.numbering_properties.is_none();
        let v3 = self.schema == "neoth.document-structure.v3"
            && self.parser_version == "docx-physical-numbering/v3"
            && self.scope == "physical-table-section-and-numbering-property-source-ranges"
            && self.section_properties.is_some()
            && self.numbering_properties.is_some();
        ensure!(
            (v1 || v2 || v3)
                && self.coordinate_system == "zip-entry-utf8-byte-offset/v1"
                && self.entry == "word/document.xml",
            "unsupported document structure contract"
        );
        if let Some(sections) = &self.section_properties {
            sections.validate(self.entry_bytes, self.scan_complete)?;
        }
        if let Some(numbering) = &self.numbering_properties {
            numbering.validate(self.entry_bytes, self.scan_complete)?;
        }
        ensure!(
            lower_sha256(&self.entry_sha256) && lower_sha256(&self.source_document.sha256),
            "invalid document structure digest"
        );
        ensure!(
            self.entry_bytes <= MAX_MEMBER_BYTES && self.source_document.bytes <= MAX_MEMBER_BYTES,
            "document structure source extent exceeds limit"
        );
        ensure!(
            !self.scan_complete || self.entry_bytes <= MAX_SCAN_BYTES,
            "complete document structure scan exceeds limit"
        );
        ensure!(
            self.tables.len() <= 32
                && self.omissions.len() <= 64
                && self.omitted_tables_observed <= 200_000,
            "document structure collection exceeds limit"
        );
        let no_omissions = self.omissions.is_empty()
            && self.omitted_tables_observed == 0
            && !self.omissions_limited;
        ensure!(
            self.complete
                == (self.scan_complete
                    && no_omissions
                    && self
                        .section_properties
                        .as_ref()
                        .is_none_or(|sections| sections.complete)
                    && self
                        .numbering_properties
                        .as_ref()
                        .is_none_or(|numbering| numbering.complete)),
            "inconsistent document structure completeness"
        );
        ensure!(
            self.scan_complete || !self.omissions.is_empty(),
            "incomplete scan lacks an omission record"
        );
        if self.entry_bytes > MAX_SCAN_BYTES {
            ensure!(
                self.tables.is_empty()
                    && !self.scan_complete
                    && self
                        .section_properties
                        .as_ref()
                        .is_none_or(|sections| sections.ranges.is_empty())
                    && self
                        .numbering_properties
                        .as_ref()
                        .is_none_or(|numbering| numbering.records.is_empty()),
                "unscanned member contains projected tables"
            );
        }

        let mut rows = 0usize;
        let mut cells = 0usize;
        let mut paragraphs = 0usize;
        let mut table_end = 0;
        for table in &self.tables {
            ordered_range(table.source_range, [0, self.entry_bytes], &mut table_end)?;
            rows = rows
                .checked_add(table.rows.len())
                .ok_or_else(|| anyhow::anyhow!("row count overflow"))?;
            ensure!(rows <= 256, "document structure row limit exceeded");
            let mut row_end = table.source_range[0];
            for row in &table.rows {
                ordered_range(row.source_range, table.source_range, &mut row_end)?;
                cells = cells
                    .checked_add(row.cells.len())
                    .ok_or_else(|| anyhow::anyhow!("cell count overflow"))?;
                ensure!(cells <= 2_048, "document structure cell limit exceeded");
                let mut cell_end = row.source_range[0];
                for cell in &row.cells {
                    ordered_range(cell.source_range, row.source_range, &mut cell_end)?;
                    paragraphs = paragraphs
                        .checked_add(cell.paragraph_source_ranges.len())
                        .ok_or_else(|| anyhow::anyhow!("paragraph count overflow"))?;
                    ensure!(
                        paragraphs <= 4_096,
                        "document structure paragraph limit exceeded"
                    );
                    let mut paragraph_end = cell.source_range[0];
                    for range in &cell.paragraph_source_ranges {
                        ordered_range(*range, cell.source_range, &mut paragraph_end)?;
                    }
                }
            }
        }
        let mut table_omissions = 0usize;
        let mut omitted_table_end = 0;
        for omission in &self.omissions {
            ensure!(
                !omission.reason.is_empty()
                    && omission.reason.len() <= 64
                    && omission
                        .reason
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
                "invalid document structure omission code"
            );
            let [start, end] = omission.source_range;
            ensure!(
                start <= end && end <= self.entry_bytes,
                "invalid document structure omission range"
            );
            match omission.scope.as_str() {
                "table" => {
                    ordered_range(
                        omission.source_range,
                        [0, self.entry_bytes],
                        &mut omitted_table_end,
                    )?;
                    table_omissions += 1;
                    ensure!(
                        self.tables
                            .iter()
                            .all(|table| end <= table.source_range[0]
                                || start >= table.source_range[1]),
                        "omitted table overlaps emitted table"
                    );
                }
                "entry_tail" => {
                    ensure!(
                        !self.scan_complete
                            && end == self.entry_bytes
                            && omitted_table_end <= start,
                        "invalid incomplete entry tail"
                    );
                    ensure!(
                        self.tables
                            .iter()
                            .all(|table| table.source_range[1] <= start),
                        "unscanned tail overlaps emitted table"
                    );
                    ensure!(
                        self.section_properties
                            .as_ref()
                            .is_none_or(|sections| sections
                                .ranges
                                .iter()
                                .all(|range| range.source_range[1] <= start)),
                        "unscanned tail overlaps emitted section"
                    );
                    ensure!(
                        self.numbering_properties
                            .as_ref()
                            .is_none_or(|numbering| numbering
                                .records
                                .iter()
                                .all(|record| record.paragraph_source_range[1] <= start)),
                        "unscanned tail overlaps emitted numbered paragraph"
                    );
                }
                "entry" => ensure!(
                    omission.reason == "metadata_limit"
                        && start == 0
                        && end == self.entry_bytes
                        && self.tables.is_empty()
                        && self
                            .section_properties
                            .as_ref()
                            .is_none_or(|sections| sections.ranges.is_empty())
                        && self
                            .numbering_properties
                            .as_ref()
                            .is_none_or(|numbering| numbering.records.is_empty()),
                    "invalid complete-entry omission"
                ),
                _ => anyhow::bail!("unsupported document structure omission scope"),
            }
        }
        ensure!(
            table_omissions <= self.omitted_tables_observed,
            "omission count understates recorded tables"
        );
        // Include every string and nested range in the actual serialized bound.
        bounded_json(self)?;
        Ok(())
    }
}

fn lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn ordered_range(range: [u64; 2], parent: [u64; 2], previous_end: &mut u64) -> Result<()> {
    ensure!(
        parent[0] <= range[0]
            && *previous_end <= range[0]
            && range[0] < range[1]
            && range[1] <= parent[1],
        "document structure range is empty, overlapping or outside its parent"
    );
    *previous_end = range[1];
    Ok(())
}

#[cfg(test)]
pub(crate) fn test_structure_value(source_sha256: &str, source_bytes: u64) -> serde_json::Value {
    serde_json::json!({
        "schema": "neoth.document-structure.v1", "parser_version": "docx-table-ranges/v1",
        "scope": "physical-table-source-ranges", "coordinate_system": "zip-entry-utf8-byte-offset/v1",
        "entry": "word/document.xml", "source_document": {"sha256": source_sha256, "bytes": source_bytes},
        "entry_sha256": "b".repeat(64), "entry_bytes": 100, "complete": true, "scan_complete": true,
        "omitted_tables_observed": 0, "omissions_limited": false,
        "tables": [{"source_range": [10, 90], "rows": [{"source_range": [20, 80], "cells": [
            {"source_range": [30, 50], "paragraph_source_ranges": [[35, 45]]},
            {"source_range": [50, 70], "paragraph_source_ranges": [[55, 65]]}
        ]}]}], "omissions": []
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structure_roundtrip_retains_source_ranges_and_rejects_other_source_binding() {
        let value = test_structure_value(&"a".repeat(64), 123);
        let structure = DocumentStructure::from_value(&value).unwrap();
        structure.validate_against(&"a".repeat(64), 123).unwrap();
        assert!(structure.validate_against(&"c".repeat(64), 123).is_err());
        assert!(structure.validate_against(&"a".repeat(64), 124).is_err());
        assert_eq!(serde_json::to_value(&structure).unwrap(), value);
        assert_eq!(
            DocumentStructure::from_json_bytes(structure.to_json().unwrap().as_bytes()).unwrap(),
            structure
        );
    }

    #[test]
    fn structure_rejects_unknown_fields_bad_coordinates_and_inconsistent_completeness() {
        let valid = test_structure_value(&"a".repeat(64), 123);
        for (pointer, value) in [
            (
                "/coordinate_system",
                serde_json::json!("chunk-byte-offset/v1"),
            ),
            ("/entry", serde_json::json!("../document.xml")),
            ("/entry_sha256", serde_json::json!("B".repeat(64))),
            (
                "/tables/0/rows/0/cells/1/source_range",
                serde_json::json!([40, 70]),
            ),
            (
                "/tables/0/rows/0/cells/0/paragraph_source_ranges/0",
                serde_json::json!([35, 60]),
            ),
            ("/tables/0/source_range", serde_json::json!([90, 90])),
            ("/complete", serde_json::json!(false)),
            ("/scan_complete", serde_json::json!(false)),
        ] {
            let mut bad = valid.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(DocumentStructure::from_value(&bad).is_err(), "{pointer}");
        }
        let mut bad = valid;
        bad["tables"][0]["layout_trusted"] = serde_json::json!(true);
        assert!(DocumentStructure::from_value(&bad).is_err());
        let mut bad = test_structure_value(&"a".repeat(64), 123);
        bad["complete"] = serde_json::json!(false);
        bad["omitted_tables_observed"] = serde_json::json!(2);
        for second in [[91, 95], [93, 99]] {
            bad["omissions"] = serde_json::json!([
                {"scope": "table", "reason": "nested_table", "source_range": [91, 95]},
                {"scope": "table", "reason": "nested_table", "source_range": second}
            ]);
            assert!(DocumentStructure::from_value(&bad).is_err());
        }
    }

    #[test]
    fn structure_admits_bounded_incomplete_members_and_zero_length_eof_tail() {
        let mut value = test_structure_value(&"a".repeat(64), 123);
        value["tables"] = serde_json::json!([]);
        value["complete"] = serde_json::json!(false);
        value["scan_complete"] = serde_json::json!(false);
        value["entry_bytes"] = serde_json::json!(MAX_SCAN_BYTES + 1);
        value["omissions"] = serde_json::json!([{"scope": "entry_tail", "reason": "entry_scan_limit", "source_range": [0, MAX_SCAN_BYTES + 1]}]);
        assert!(DocumentStructure::from_value(&value).is_ok());
        value["entry_bytes"] = serde_json::json!(0);
        value["omissions"][0] = serde_json::json!({"scope": "entry_tail", "reason": "incomplete_document", "source_range": [0, 0]});
        assert!(DocumentStructure::from_value(&value).is_ok());
        value["entry_bytes"] = serde_json::json!(MAX_MEMBER_BYTES + 1);
        assert!(DocumentStructure::from_value(&value).is_err());
    }

    #[test]
    fn structure_checks_actual_json_and_global_collection_limits() {
        assert!(
            DocumentStructure::from_json_bytes(&vec![b' '; MAX_STRUCTURE_JSON_BYTES + 1]).is_err()
        );
        let mut value = test_structure_value(&"a".repeat(64), 123);
        value["unknown"] = serde_json::json!("x".repeat(MAX_STRUCTURE_JSON_BYTES));
        assert!(DocumentStructure::from_value(&value).is_err());
        let mut value = test_structure_value(&"a".repeat(64), 123);
        value["tables"] = serde_json::Value::Array(vec![value["tables"][0].clone(); 33]);
        assert!(DocumentStructure::from_value(&value).is_err());
        let mut value = test_structure_value(&"a".repeat(64), 123);
        value["omissions"] = serde_json::Value::Array(vec![
            serde_json::json!({"scope": "table", "reason": "nested_table", "source_range": [91, 99]});
            65
        ]);
        value["omitted_tables_observed"] = serde_json::json!(65);
        value["complete"] = serde_json::json!(false);
        assert!(DocumentStructure::from_value(&value).is_err());
    }

    #[test]
    fn structure_enforces_row_cell_and_paragraph_caps_across_parent_collections() {
        for (kind, cap) in [("rows", 256usize), ("cells", 2_048), ("paragraphs", 4_096)] {
            let mut value = test_structure_value(&"a".repeat(64), 123);
            value["entry_bytes"] = serde_json::json!(100_000);
            value["tables"][0]["source_range"] = serde_json::json!([1, 99_999]);
            match kind {
                "rows" => value["tables"][0]["rows"] = serde_json::Value::Array((0..=cap)
                    .map(|i| serde_json::json!({"source_range": [10+i*10, 15+i*10], "cells": []})).collect()),
                "cells" => value["tables"][0]["rows"] = serde_json::json!([{
                    "source_range": [2, 99_998], "cells": (0..=cap)
                        .map(|i| serde_json::json!({"source_range": [10+i*10, 15+i*10], "paragraph_source_ranges": []})).collect::<Vec<_>>()
                }]),
                _ => value["tables"][0]["rows"] = serde_json::json!([{
                    "source_range": [2, 99_998], "cells": [{"source_range": [3, 99_997],
                        "paragraph_source_ranges": (0..=cap).map(|i| [10+i*10, 15+i*10]).collect::<Vec<_>>()
                    }]
                }]),
            }
            assert!(DocumentStructure::from_value(&value).is_err(), "{kind}");
            let collection = match kind {
                "rows" => &mut value["tables"][0]["rows"],
                "cells" => &mut value["tables"][0]["rows"][0]["cells"],
                _ => &mut value["tables"][0]["rows"][0]["cells"][0]["paragraph_source_ranges"],
            };
            collection.as_array_mut().unwrap().pop();
            assert!(DocumentStructure::from_value(&value).is_ok(), "{kind}");
            let mut second = value["tables"][0].clone();
            let shift = |range: &mut serde_json::Value| {
                for endpoint in range.as_array_mut().unwrap() {
                    *endpoint = serde_json::json!(endpoint.as_u64().unwrap() + 100_000);
                }
            };
            shift(&mut second["source_range"]);
            for row in second["rows"].as_array_mut().unwrap() {
                shift(&mut row["source_range"]);
                for cell in row["cells"].as_array_mut().unwrap() {
                    shift(&mut cell["source_range"]);
                    for range in cell["paragraph_source_ranges"].as_array_mut().unwrap() {
                        shift(range);
                    }
                }
            }
            fn range_collection<'a>(
                table: &'a mut serde_json::Value,
                kind: &str,
            ) -> &'a mut serde_json::Value {
                match kind {
                    "rows" => &mut table["rows"],
                    "cells" => &mut table["rows"][0]["cells"],
                    _ => &mut table["rows"][0]["cells"][0]["paragraph_source_ranges"],
                }
            }
            range_collection(&mut value["tables"][0], kind)
                .as_array_mut()
                .unwrap()
                .truncate(cap / 2);
            range_collection(&mut second, kind)
                .as_array_mut()
                .unwrap()
                .truncate(cap / 2 + 1);
            value["entry_bytes"] = serde_json::json!(200_000);
            value["tables"].as_array_mut().unwrap().push(second);
            assert!(
                DocumentStructure::from_value(&value).is_err(),
                "global {kind}"
            );
        }
    }

    fn v2_structure() -> serde_json::Value {
        let mut value = test_structure_value(&"a".repeat(64), 123);
        value["schema"] = serde_json::json!("neoth.document-structure.v2");
        value["parser_version"] = serde_json::json!("docx-table-section-properties/v2");
        value["scope"] = serde_json::json!("physical-table-and-section-property-source-ranges");
        value["section_properties"] = serde_json::json!({
            "complete": true, "omitted_observed": 0, "omissions_limited": false,
            "ranges": [{"context": "body", "source_range": [91, 99]}], "omissions": []
        });
        value
    }

    #[test]
    fn section_structure_v2_roundtrips_without_reinterpreting_historical_v1() {
        for value in [test_structure_value(&"a".repeat(64), 123), v2_structure()] {
            let structure = DocumentStructure::from_value(&value).unwrap();
            assert_eq!(serde_json::to_value(&structure).unwrap(), value);
            assert_eq!(
                DocumentStructure::from_json_bytes(structure.to_json().unwrap().as_bytes())
                    .unwrap(),
                structure
            );
        }
        for version in [1, 2] {
            let mut value = if version == 1 {
                test_structure_value(&"a".repeat(64), 123)
            } else {
                v2_structure()
            };
            value["section_properties"] = serde_json::Value::Null;
            assert!(DocumentStructure::from_value(&value).is_err());
        }
        let mut old = test_structure_value(&"a".repeat(64), 123);
        old["section_properties"] = v2_structure()["section_properties"].clone();
        assert!(DocumentStructure::from_value(&old).is_err());
        let mut new = v2_structure();
        new.as_object_mut().unwrap().remove("section_properties");
        assert!(DocumentStructure::from_value(&new).is_err());
    }

    #[test]
    fn section_structure_rejects_unknown_contexts_ranges_and_false_completeness() {
        for (pointer, replacement) in [
            ("/parser_version", serde_json::json!("docx-table-ranges/v1")),
            ("/section_properties/complete", serde_json::json!(false)),
            ("/section_properties/omitted_observed", serde_json::json!(1)),
            (
                "/section_properties/ranges/0/context",
                serde_json::json!("rendered_page"),
            ),
            (
                "/section_properties/ranges/0/source_range",
                serde_json::json!([91, 101]),
            ),
            (
                "/section_properties/ranges/0/source_range",
                serde_json::json!([99, 91]),
            ),
        ] {
            let mut value = v2_structure();
            *value.pointer_mut(pointer).unwrap() = replacement;
            assert!(DocumentStructure::from_value(&value).is_err(), "{pointer}");
        }
        let mut value = v2_structure();
        value["section_properties"]["ranges"] = serde_json::json!([
            {"context":"body","source_range":[91,99]},
            {"context":"body","source_range":[95,100]}
        ]);
        assert!(DocumentStructure::from_value(&value).is_err());
        let mut value = v2_structure();
        value["complete"] = serde_json::json!(false);
        value["section_properties"]["complete"] = serde_json::json!(false);
        value["section_properties"]["omitted_observed"] = serde_json::json!(1);
        value["section_properties"]["omissions"] = serde_json::json!([
            {"reason":"unsupported_section_context","source_range":[95,100]}
        ]);
        assert!(DocumentStructure::from_value(&value).is_err());
    }

    fn numbering_structure_v3() -> serde_json::Value {
        let mut value = v2_structure();
        value["schema"] = serde_json::json!("neoth.document-structure.v3");
        value["parser_version"] = serde_json::json!("docx-physical-numbering/v3");
        value["scope"] =
            serde_json::json!("physical-table-section-and-numbering-property-source-ranges");
        value["numbering_properties"] = serde_json::json!({
            "complete": true,
            "records": [{
                "paragraph_source_range": [11,80],
                "numbering_properties_source_range": [12,20],
                "num_id": 2, "level": null, "kind": "numbering_reference"
            }],
            "omitted_observed": 0, "omissions_limited": false, "omissions": []
        });
        value
    }
    #[test]
    fn numbering_structure_versions_roundtrip_and_enforce_field_presence() {
        let hash = "a".repeat(64);
        for value in [
            test_structure_value(&hash, 123),
            v2_structure(),
            numbering_structure_v3(),
        ] {
            let decoded = DocumentStructure::from_value(&value).unwrap();
            assert_eq!(serde_json::to_value(&decoded).unwrap(), value);
            assert_eq!(
                DocumentStructure::from_json_bytes(decoded.to_json().unwrap().as_bytes()).unwrap(),
                decoded
            );
        }
        for mut value in [test_structure_value(&hash, 123), v2_structure()] {
            value["numbering_properties"] =
                numbering_structure_v3()["numbering_properties"].clone();
            assert!(DocumentStructure::from_value(&value).is_err());
        }
        let mut missing = numbering_structure_v3();
        missing
            .as_object_mut()
            .unwrap()
            .remove("numbering_properties");
        assert!(DocumentStructure::from_value(&missing).is_err());
        for mut value in [
            test_structure_value(&hash, 123),
            v2_structure(),
            numbering_structure_v3(),
        ] {
            value["numbering_properties"] = serde_json::Value::Null;
            assert!(DocumentStructure::from_value(&value).is_err());
        }
    }
    #[test]
    fn numbering_structure_rejects_invalid_records_metadata_and_bindings() {
        for (pointer, replacement) in [
            (
                "/numbering_properties/records/0/kind",
                serde_json::json!("numbering_removed"),
            ),
            (
                "/numbering_properties/records/0/num_id",
                serde_json::json!(0),
            ),
            (
                "/numbering_properties/records/0/level",
                serde_json::json!(9),
            ),
            (
                "/numbering_properties/records/0/numbering_properties_source_range",
                serde_json::json!([10, 20]),
            ),
            (
                "/numbering_properties/records/0/numbering_properties_source_range",
                serde_json::json!([11, 20]),
            ),
            ("/schema", serde_json::json!("neoth.document-structure.v99")),
            ("/parser_version", serde_json::json!("unknown-parser")),
            ("/scope", serde_json::json!("unknown-scope")),
            ("/numbering_properties/complete", serde_json::json!(false)),
            (
                "/numbering_properties/omitted_observed",
                serde_json::json!(1),
            ),
        ] {
            let mut value = numbering_structure_v3();
            *value.pointer_mut(pointer).unwrap() = replacement;
            assert!(DocumentStructure::from_value(&value).is_err(), "{pointer}");
        }
        let mut duplicate = numbering_structure_v3();
        let record = duplicate["numbering_properties"]["records"][0].clone();
        duplicate["numbering_properties"]["records"]
            .as_array_mut()
            .unwrap()
            .push(record);
        assert!(DocumentStructure::from_value(&duplicate).is_err());
        let mut overlap = numbering_structure_v3();
        overlap["complete"] = serde_json::json!(false);
        overlap["numbering_properties"]["complete"] = serde_json::json!(false);
        overlap["numbering_properties"]["omitted_observed"] = serde_json::json!(1);
        overlap["numbering_properties"]["omissions"] = serde_json::json!([{
            "reason": "unsupported_numbering_context", "source_range": [70,90]
        }]);
        assert!(DocumentStructure::from_value(&overlap).is_err());
        let decoded = DocumentStructure::from_value(&numbering_structure_v3()).unwrap();
        assert!(decoded.validate_against(&"b".repeat(64), 123).is_err());
        assert!(decoded.validate_against(&"a".repeat(64), 124).is_err());
    }
}
