//! Validated source-level DOCX ranges. These remain extractor assertions:
//! the index has neither the original ZIP member nor a chunk-to-XML mapping.
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
        ensure!(
            self.schema == "neoth.document-structure.v1"
                && self.parser_version == "docx-table-ranges/v1"
                && self.scope == "physical-table-source-ranges"
                && self.coordinate_system == "zip-entry-utf8-byte-offset/v1"
                && self.entry == "word/document.xml",
            "unsupported document structure contract"
        );
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
            self.complete == (self.scan_complete && no_omissions),
            "inconsistent document structure completeness"
        );
        ensure!(
            self.scan_complete || !self.omissions.is_empty(),
            "incomplete scan lacks an omission record"
        );
        if self.entry_bytes > MAX_SCAN_BYTES {
            ensure!(
                self.tables.is_empty() && !self.scan_complete,
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
                }
                "entry" => ensure!(
                    omission.reason == "metadata_limit"
                        && start == 0
                        && end == self.entry_bytes
                        && self.tables.is_empty(),
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
}
