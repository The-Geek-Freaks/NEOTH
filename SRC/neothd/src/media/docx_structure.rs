//! Bounded physical DOCX table, section and numbering ranges, never a layout model.
#[path = "docx_lists.rs"]
mod lists;
#[path = "docx_sections.rs"]
mod sections;
use quick_xml::{NsReader, events::Event, name::ResolveResult};
use serde::Serialize;
use sha2::{Digest, Sha256};

const WORD: &[u8] = b"http://schemas.openxmlformats.org/wordprocessingml/2006/main";
const STRICT_WORD: &[u8] = b"http://purl.oclc.org/ooxml/wordprocessingml/main";

#[derive(Clone, Copy)]
struct Limits {
    entry_bytes: usize,
    events: usize,
    depth: usize,
    tables: usize,
    rows: usize,
    cells: usize,
    paragraphs: usize,
    omissions: usize,
    metadata_bytes: usize,
}

const LIMITS: Limits = Limits {
    entry_bytes: 8 * 1024 * 1024,
    events: 200_000,
    depth: 128,
    tables: 32,
    rows: 256,
    cells: 2_048,
    paragraphs: 4_096,
    omissions: 64,
    metadata_bytes: 256 * 1024,
};

#[derive(Serialize)]
struct Table {
    source_range: [usize; 2],
    rows: Vec<Row>,
}

#[derive(Serialize)]
struct Row {
    source_range: [usize; 2],
    cells: Vec<Cell>,
}

#[derive(Serialize)]
struct Cell {
    source_range: [usize; 2],
    paragraph_source_ranges: Vec<[usize; 2]>,
}

#[derive(Serialize)]
struct Omission {
    scope: &'static str,
    reason: &'static str,
    source_range: [usize; 2],
}

#[derive(Serialize)]
struct SourceDocument {
    sha256: String,
    bytes: usize,
}

#[derive(Serialize)]
struct Projection {
    source_document: SourceDocument,
    schema: &'static str,
    parser_version: &'static str,
    scope: &'static str,
    coordinate_system: &'static str,
    entry: &'static str,
    entry_sha256: String,
    entry_bytes: usize,
    complete: bool,
    scan_complete: bool,
    omitted_tables_observed: usize,
    omissions_limited: bool,
    tables: Vec<Table>,
    omissions: Vec<Omission>,
    section_properties: Option<sections::Projection>,
    numbering_properties: Option<lists::Projection>,
}

struct Frame {
    local: Vec<u8>,
    word: bool,
    properties: bool,
    start: usize,
}

impl Frame {
    fn is(&self, local: &[u8]) -> bool {
        self.word && self.local == local
    }
}

struct BuildingTable {
    value: Table,
    depth: usize,
    reason: Option<&'static str>,
}

struct State {
    out: Projection,
    stack: Vec<Frame>,
    table: Option<BuildingTable>,
    rows: usize,
    cells: usize,
    paragraphs: usize,
    root_seen: bool,
    body_seen: bool,
    declaration_seen: bool,
    limits: Limits,
    sections: sections::Sections,
    lists: lists::Projector,
}

impl State {
    fn omit(&mut self, scope: &'static str, reason: &'static str, range: [usize; 2]) {
        self.out.complete = false;
        if scope == "table" {
            self.out.omitted_tables_observed += 1;
        }
        if self.out.omissions.len() < self.limits.omissions {
            self.out.omissions.push(Omission {
                scope,
                reason,
                source_range: range,
            });
        } else {
            self.out.omissions_limited = true;
        }
    }

    fn stop(&mut self, reason: &'static str, offset: usize) {
        let start = if let Some(table) = self.table.take() {
            self.out.omitted_tables_observed += 1;
            table.value.source_range[0]
        } else {
            offset
        };
        self.omit(
            "entry_tail",
            reason,
            [start.min(self.out.entry_bytes), self.out.entry_bytes],
        );
        self.out.scan_complete = false;
    }

    fn reject_table(&mut self, reason: &'static str) {
        if let Some(table) = &mut self.table {
            table.reason.get_or_insert(reason);
        }
    }

    fn begin(&mut self, local: &[u8], word: bool, start: usize) -> Result<(), &'static str> {
        if self.stack.len() >= self.limits.depth || local.len() > 256 {
            return Err("depth_or_name_limit");
        }
        if self.stack.is_empty() {
            if self.root_seen || !word || local != b"document" {
                return Err("unsupported_document_root");
            }
            self.root_seen = true;
        }
        let parent = self.stack.last();
        let parent_is = |name: &[u8]| parent.is_some_and(|frame| frame.is(name));
        if word && local == b"body" && self.stack.len() == 1 && parent_is(b"document") {
            if self.body_seen {
                return Err("duplicate_document_body");
            }
            self.body_seen = true;
        }
        let mut properties = parent.is_some_and(|frame| frame.properties);
        if word && local == b"tbl" {
            if self.table.is_some() {
                self.reject_table("nested_table");
            } else {
                let supported = self.stack.len() == 2 && parent_is(b"body");
                self.table = Some(BuildingTable {
                    value: Table {
                        source_range: [start, 0],
                        rows: Vec::new(),
                    },
                    depth: self.stack.len(),
                    reason: (!supported).then_some("unsupported_table_context"),
                });
            }
        } else if let Some(table) = &mut self.table
            && table.reason.is_none()
        {
            if !word {
                table.reason = Some("foreign_table_structure");
            } else if matches!(
                local,
                b"gridSpan"
                    | b"vMerge"
                    | b"hMerge"
                    | b"gridBefore"
                    | b"gridAfter"
                    | b"cellMerge"
                    | b"tblPrChange"
                    | b"trPrChange"
                    | b"tcPrChange"
                    | b"ins"
                    | b"del"
                    | b"moveFrom"
                    | b"moveTo"
            ) {
                table.reason = Some("unsupported_table_semantics");
            } else {
                let valid = match local {
                    b"tr" if parent_is(b"tbl") => {
                        self.rows += 1;
                        if self.rows > self.limits.rows {
                            table.reason = Some("row_limit");
                        } else {
                            table.value.rows.push(Row {
                                source_range: [start, 0],
                                cells: Vec::new(),
                            });
                        }
                        true
                    }
                    b"tc" if parent_is(b"tr") => {
                        self.cells += 1;
                        if self.cells > self.limits.cells {
                            table.reason = Some("cell_limit");
                        } else if let Some(row) = table.value.rows.last_mut() {
                            row.cells.push(Cell {
                                source_range: [start, 0],
                                paragraph_source_ranges: Vec::new(),
                            });
                        } else {
                            table.reason = Some("invalid_table_hierarchy");
                        }
                        true
                    }
                    b"p" if parent_is(b"tc") => {
                        self.paragraphs += 1;
                        if self.paragraphs > self.limits.paragraphs {
                            table.reason = Some("paragraph_limit");
                        } else if let Some(cell) = table
                            .value
                            .rows
                            .last_mut()
                            .and_then(|row| row.cells.last_mut())
                        {
                            cell.paragraph_source_ranges.push([start, 0]);
                        } else {
                            table.reason = Some("invalid_table_hierarchy");
                        }
                        true
                    }
                    // Structural nodes are never accepted inside opaque properties.
                    b"tr" | b"tc" | b"p" | b"document" | b"body" => false,
                    _ if properties => true,
                    b"tblPr" | b"tblGrid" if parent_is(b"tbl") => {
                        properties = true;
                        true
                    }
                    b"trPr" if parent_is(b"tr") => {
                        properties = true;
                        true
                    }
                    b"tcPr" if parent_is(b"tc") => {
                        properties = true;
                        true
                    }
                    b"pPr" if parent_is(b"p") => {
                        properties = true;
                        true
                    }
                    b"rPr" if parent_is(b"r") => {
                        properties = true;
                        true
                    }
                    b"r" if parent_is(b"p") || parent_is(b"hyperlink") => true,
                    b"t" | b"tab" | b"br" | b"cr" if parent_is(b"r") => true,
                    b"hyperlink" | b"bookmarkStart" | b"bookmarkEnd" | b"proofErr"
                        if parent_is(b"p") =>
                    {
                        true
                    }
                    _ => false,
                };
                if !valid {
                    table.reason = Some("unsupported_table_structure");
                }
            }
        }
        self.stack.push(Frame {
            local: local.to_vec(),
            word,
            properties,
            start,
        });
        Ok(())
    }

    fn end(&mut self, end: usize) -> Result<(), &'static str> {
        self.sections.end(self.stack.len(), end);
        self.lists.end(self.stack.len(), end);
        let frame = self.stack.pop().ok_or("invalid_xml_hierarchy")?;
        let Some(table) = &mut self.table else {
            return Ok(());
        };
        if frame.is(b"tbl") && self.stack.len() == table.depth {
            let mut table = self.table.take().ok_or("invalid_table_hierarchy")?;
            table.value.source_range[1] = end;
            if table.reason.is_none() && self.out.tables.len() >= self.limits.tables {
                table.reason = Some("table_limit");
            }
            if let Some(reason) = table.reason {
                self.omit("table", reason, table.value.source_range);
            } else {
                self.out.tables.push(table.value);
            }
        } else if table.reason.is_none() {
            if frame.is(b"tr") {
                if let Some(row) = table.value.rows.last_mut() {
                    row.source_range[1] = end;
                }
            } else if frame.is(b"tc") {
                if let Some(cell) = table
                    .value
                    .rows
                    .last_mut()
                    .and_then(|row| row.cells.last_mut())
                {
                    cell.source_range[1] = end;
                }
            } else if frame.is(b"p")
                && let Some(paragraph) = table
                    .value
                    .rows
                    .last_mut()
                    .and_then(|row| row.cells.last_mut())
                    .and_then(|cell| cell.paragraph_source_ranges.last_mut())
            {
                paragraph[1] = end;
            }
        }
        Ok(())
    }
}

fn legal_xml_char(ch: char) -> bool {
    matches!(ch, '\t' | '\r' | '\n' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
}

pub(super) fn project(xml: &str, source_sha256: &str, source_bytes: usize) -> serde_json::Value {
    project_with_limits(xml, source_sha256, source_bytes, LIMITS)
}

fn project_with_limits(
    xml: &str,
    source_sha256: &str,
    source_bytes: usize,
    limits: Limits,
) -> serde_json::Value {
    let mut state = State {
        out: Projection {
            source_document: SourceDocument {
                sha256: source_sha256.to_owned(),
                bytes: source_bytes,
            },
            schema: "neoth.document-structure.v3",
            parser_version: "docx-physical-numbering/v3",
            scope: "physical-table-section-and-numbering-property-source-ranges",
            coordinate_system: "zip-entry-utf8-byte-offset/v1",
            entry: "word/document.xml",
            entry_sha256: hex::encode(Sha256::digest(xml.as_bytes())),
            entry_bytes: xml.len(),
            complete: true,
            scan_complete: false,
            omitted_tables_observed: 0,
            omissions_limited: false,
            tables: Vec::new(),
            omissions: Vec::new(),
            section_properties: None,
            numbering_properties: None,
        },
        stack: Vec::new(),
        table: None,
        rows: 0,
        cells: 0,
        paragraphs: 0,
        root_seen: false,
        body_seen: false,
        declaration_seen: false,
        sections: sections::Sections::new(),
        lists: lists::Projector::default(),
        limits,
    };
    if xml.len() > limits.entry_bytes {
        state.stop("entry_scan_limit", 0);
    } else {
        scan(xml, &mut state);
    }
    let sections = std::mem::replace(&mut state.sections, sections::Sections::new())
        .finish(state.out.scan_complete, xml.len());
    state.out.complete &= sections.complete;
    state.out.section_properties = Some(sections);
    let mut numbering = std::mem::take(&mut state.lists).finish(state.out.scan_complete, xml.len());
    if let Some(tail) = state
        .out
        .omissions
        .iter()
        .find(|item| item.scope == "entry_tail")
    {
        numbering.discard_from(tail.source_range[0]);
    }
    state.out.complete &= numbering.complete;
    state.out.numbering_properties = Some(numbering);
    // The fixed metadata header plus bounded diagnostics fits within the production
    // cap even when every table is omitted. This measures the actual JSON encoding.
    if serde_json::to_vec(&state.out)
        .expect("range projection is JSON-safe")
        .len()
        > limits.metadata_bytes
    {
        state.out.omitted_tables_observed += state.out.tables.len();
        state.out.tables.clear();
        if let Some(sections) = &mut state.out.section_properties {
            sections.discard_for_metadata_limit(xml.len());
        }
        if let Some(numbering) = &mut state.out.numbering_properties {
            numbering.discard_for_metadata_limit(xml.len());
        }
        state.out.complete = false;
        // Keep the summary first so trimming detailed records cannot erase why
        // otherwise valid tables disappeared. Production always allows 64 records.
        state.out.omissions.insert(
            0,
            Omission {
                scope: "entry",
                reason: "metadata_limit",
                source_range: [0, xml.len()],
            },
        );
        if state.out.omissions.len() > limits.omissions.max(1) {
            state.out.omissions.truncate(limits.omissions.max(1));
            state.out.omissions_limited = true;
        }
        while state.out.omissions.len() > 1
            && serde_json::to_vec(&state.out)
                .expect("range projection is JSON-safe")
                .len()
                > limits.metadata_bytes
        {
            state.out.omissions.pop();
            state.out.omissions_limited = true;
        }
    }
    serde_json::to_value(state.out).expect("range projection is JSON-safe")
}

fn scan(xml: &str, state: &mut State) {
    // Reader positions exclude a leading UTF-8 BOM. Parse an explicit slice
    // and translate every position back to the unchanged archive-member bytes.
    let input = xml.strip_prefix('\u{feff}').unwrap_or(xml);
    let origin = xml.len() - input.len();
    if input.starts_with('\u{feff}') {
        state.stop("text_outside_root", origin);
        return;
    }
    let mut reader = NsReader::from_str(input);
    reader.config_mut().check_comments = true;
    reader.config_mut().check_end_names = true;
    reader.resolver_mut().set_max_declarations_per_element(64);
    for _ in 0..state.limits.events {
        let start = origin + reader.buffer_position() as usize;
        let (namespace, event) = match reader.read_resolved_event() {
            Ok(event) => event,
            Err(_) => {
                state.stop("malformed_xml", start);
                return;
            }
        };
        let word = matches!(&namespace, ResolveResult::Bound(ns) if ns.as_ref() == WORD || ns.as_ref() == STRICT_WORD);
        if matches!(namespace, ResolveResult::Unknown(_)) {
            state.stop("unbound_namespace_prefix", start);
            return;
        }
        let end = origin + reader.buffer_position() as usize;
        let empty = matches!(&event, Event::Empty(_));
        let result = match event {
            Event::Start(element) | Event::Empty(element) => {
                let mut attributes_valid = true;
                let mut foreign_attributes = false;
                let mut numbering_value = lists::Val::Absent;
                let mut numbering_attributes_supported = true;
                let numbering_element =
                    word && matches!(element.local_name().as_ref(), b"numPr" | b"numId" | b"ilvl");
                for (index, attribute) in element.attributes().enumerate() {
                    let Ok(attribute) = attribute else {
                        attributes_valid = false;
                        break;
                    };
                    if index >= 64
                        || attribute.key.as_ref().len() > 256
                        || attribute.value.len() > 4_096
                    {
                        attributes_valid = false;
                        break;
                    }
                    let Ok(value) = std::str::from_utf8(attribute.value.as_ref()) else {
                        attributes_valid = false;
                        break;
                    };
                    if !value.chars().all(legal_xml_char)
                        || !quick_xml::escape::unescape(value)
                            .is_ok_and(|value| value.chars().all(legal_xml_char))
                    {
                        attributes_valid = false;
                        break;
                    }
                    if attribute.key.as_ref() != b"xmlns"
                        && !attribute.key.as_ref().starts_with(b"xmlns:")
                    {
                        let (namespace, local) = reader.resolver().resolve_attribute(attribute.key);
                        if numbering_element {
                            let word_attribute = matches!(&namespace, ResolveResult::Bound(ns)
                                if ns.as_ref() == WORD || ns.as_ref() == STRICT_WORD);
                            if word_attribute
                                && local.as_ref() == b"val"
                                && matches!(element.local_name().as_ref(), b"numId" | b"ilvl")
                            {
                                if !matches!(numbering_value, lists::Val::Absent) {
                                    numbering_attributes_supported = false;
                                    numbering_value = lists::Val::Invalid;
                                } else {
                                    numbering_value = quick_xml::escape::unescape(value)
                                        .ok()
                                        .and_then(|value| {
                                            if !value.is_empty()
                                                && value.bytes().all(|byte| byte.is_ascii_digit())
                                            {
                                                value.parse::<u32>().ok()
                                            } else {
                                                None
                                            }
                                        })
                                        .map(lists::Val::Number)
                                        .unwrap_or(lists::Val::Invalid);
                                }
                            } else {
                                numbering_attributes_supported = false;
                            }
                        }
                        match namespace {
                            ResolveResult::Unknown(_) => {
                                attributes_valid = false;
                                break;
                            }
                            ResolveResult::Bound(ns)
                                if ns.as_ref() != WORD
                                    && ns.as_ref() != STRICT_WORD
                                    && ns.as_ref() != b"http://www.w3.org/XML/1998/namespace" =>
                            {
                                foreign_attributes = true
                            }
                            _ => {}
                        }
                    }
                }
                if !attributes_valid {
                    Err("invalid_or_unbounded_attributes")
                } else {
                    state
                        .begin(element.local_name().as_ref(), word, start)
                        .and_then(|()| {
                            state.sections.begin(&state.stack, start);
                            state.lists.begin(
                                &state.stack,
                                start,
                                numbering_value,
                                numbering_attributes_supported,
                            );
                            if foreign_attributes {
                                state.sections.reject("foreign_attribute_semantics");
                                state.reject_table("foreign_attribute_semantics");
                            }
                            if empty { state.end(end) } else { Ok(()) }
                        })
                }
            }
            Event::End(_) => state.end(end),
            Event::DocType(_) => Err("unsupported_doctype"),
            Event::PI(_) => Err("unsupported_processing_instruction"),
            Event::Decl(declaration) => {
                let valid = !state.declaration_seen
                    && !state.root_seen
                    && declaration
                        .version()
                        .is_ok_and(|value| value.as_ref() == b"1.0")
                    && declaration.encoding().is_none_or(|value| {
                        value.is_ok_and(|name| name.eq_ignore_ascii_case(b"utf-8"))
                    });
                state.declaration_seen = true;
                if valid {
                    Ok(())
                } else {
                    Err("unsupported_xml_declaration")
                }
            }
            Event::Text(text) => {
                let text: &[u8] = text.as_ref();
                let valid =
                    std::str::from_utf8(text).is_ok_and(|value| value.chars().all(legal_xml_char));
                if !valid {
                    Err("invalid_xml_text")
                } else if state.stack.is_empty() && !text.iter().all(u8::is_ascii_whitespace) {
                    Err("text_outside_root")
                } else {
                    if !text.iter().all(u8::is_ascii_whitespace) {
                        state.sections.reject("unsupported_section_text");
                        state
                            .lists
                            .reject_property_content("unsupported_numbering_text");
                    }
                    if state.table.is_some()
                        && !state.stack.last().is_some_and(|frame| frame.is(b"t"))
                        && !text.iter().all(u8::is_ascii_whitespace)
                    {
                        state.reject_table("unsupported_text_position");
                    }
                    Ok(())
                }
            }
            Event::CData(data) => {
                if state.stack.is_empty() {
                    Err("cdata_outside_root")
                } else if !std::str::from_utf8(data.as_ref())
                    .is_ok_and(|value| value.chars().all(legal_xml_char))
                {
                    Err("invalid_xml_text")
                } else {
                    state.sections.reject("unsupported_section_cdata");
                    state
                        .lists
                        .reject_property_content("unsupported_numbering_cdata");
                    state.reject_table("unsupported_cdata");
                    Ok(())
                }
            }
            Event::GeneralRef(reference) => {
                let name: &[u8] = reference.as_ref();
                let valid = match reference.resolve_char_ref() {
                    Ok(Some(ch)) => legal_xml_char(ch),
                    Ok(None) => matches!(name, b"amp" | b"lt" | b"gt" | b"apos" | b"quot"),
                    Err(_) => false,
                };
                if !valid {
                    Err("unsupported_entity")
                } else if state.stack.is_empty() {
                    Err("text_outside_root")
                } else {
                    state.sections.reject("unsupported_section_entity");
                    state
                        .lists
                        .reject_property_content("unsupported_numbering_entity");
                    if !state.stack.last().is_some_and(|frame| frame.is(b"t")) {
                        state.reject_table("unsupported_text_position");
                    }
                    Ok(())
                }
            }
            Event::Comment(_) => Ok(()),
            Event::Eof => {
                if state.root_seen
                    && state.body_seen
                    && state.stack.is_empty()
                    && state.table.is_none()
                {
                    state.out.scan_complete = true;
                } else {
                    state.stop("incomplete_document", start);
                }
                return;
            }
        };
        if let Err(reason) = result {
            state.stop(reason, start);
            return;
        }
    }
    state.stop("event_limit", origin + reader.buffer_position() as usize);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const SOURCE: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn wrap(body: &str) -> String {
        format!(
            "<w:document xmlns:w=\"{}\"><w:body>{body}</w:body></w:document>",
            std::str::from_utf8(WORD).unwrap()
        )
    }

    fn table(body: &str) -> String {
        format!("<w:tbl><w:tr><w:tc>{body}</w:tc></w:tr></w:tbl>")
    }

    fn paragraph(text: &str) -> String {
        format!("<w:p><w:r><w:t>{text}</w:t></w:r></w:p>")
    }

    fn view(xml: &str) -> Value {
        project(xml, SOURCE, 123)
    }

    fn slice<'a>(xml: &'a str, range: &Value) -> &'a str {
        let start = range[0].as_u64().unwrap() as usize;
        let end = range[1].as_u64().unwrap() as usize;
        xml.get(start..end)
            .expect("range is on exact UTF-8 boundaries")
    }

    #[test]
    fn docx_ranges_bind_exact_member_bytes_and_preserve_cells_and_paragraphs() {
        let p1 = paragraph("Grüße &amp; Ω");
        let p2 = paragraph("second");
        let p3 = paragraph("right");
        let row = format!("<w:tr><w:tc>{p1}{p2}</w:tc><w:tc>{p3}</w:tc></w:tr>");
        let tbl = format!("<w:tbl>{row}</w:tbl>");
        for prefix in ["", "\u{feff}"] {
            let xml = format!(
                "{prefix}<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n{}",
                wrap(&tbl)
            );
            let out = view(&xml);
            assert_eq!(out["complete"], true);
            assert_eq!(out["scan_complete"], true);
            assert_eq!(out["entry_bytes"], xml.len());
            assert_eq!(
                out["entry_sha256"],
                hex::encode(Sha256::digest(xml.as_bytes()))
            );
            assert_eq!(out["source_document"]["sha256"], SOURCE);
            assert_eq!(out["source_document"]["bytes"], 123);
            let t = &out["tables"][0];
            assert_eq!(slice(&xml, &t["source_range"]), tbl);
            assert_eq!(slice(&xml, &t["rows"][0]["source_range"]), row);
            let cells = t["rows"][0]["cells"].as_array().unwrap();
            assert_eq!(cells.len(), 2);
            assert_eq!(
                slice(&xml, &cells[0]["source_range"]),
                format!("<w:tc>{p1}{p2}</w:tc>")
            );
            assert_eq!(slice(&xml, &cells[0]["paragraph_source_ranges"][0]), p1);
            assert_eq!(slice(&xml, &cells[0]["paragraph_source_ranges"][1]), p2);
            assert_eq!(slice(&xml, &cells[1]["paragraph_source_ranges"][0]), p3);
        }
    }

    #[test]
    fn docx_ranges_resolve_alias_default_and_strict_namespaces_without_foreign_tables() {
        for namespace in [WORD, STRICT_WORD] {
            let uri = std::str::from_utf8(namespace).unwrap();
            let aliased = format!(
                "<x:document xmlns:x=\"{uri}\"><x:body><x:tbl><x:tr><x:tc><x:p/></x:tc></x:tr></x:tbl></x:body></x:document>"
            );
            let default_ns = format!(
                "<document xmlns=\"{uri}\"><body><tbl><tr><tc><p/></tc></tr></tbl></body></document>"
            );
            for xml in [aliased, default_ns] {
                let out = view(&xml);
                assert_eq!(out["complete"], true);
                assert_eq!(out["tables"].as_array().unwrap().len(), 1);
                assert!(
                    slice(
                        &xml,
                        &out["tables"][0]["rows"][0]["cells"][0]["paragraph_source_ranges"][0]
                    )
                    .ends_with("/>")
                );
            }
        }
        let xml = wrap("<f:tbl xmlns:f=\"urn:foreign\"><f:tr><f:tc/></f:tr></f:tbl>");
        assert_eq!(view(&xml)["tables"].as_array().unwrap().len(), 0);
        let foreign_root = "<document xmlns=\"urn:foreign\"><body><tbl/></body></document>";
        assert_eq!(view(foreign_root)["complete"], false);
    }

    #[test]
    fn docx_ranges_omit_merged_revised_and_offset_tables_whole() {
        for properties in [
            "<w:tcPr><w:gridSpan w:val=\"2\"/></w:tcPr>",
            "<w:tcPr><w:vMerge/></w:tcPr>",
            "<w:tcPr><w:hMerge/></w:tcPr>",
            "<w:tcPr><w:gridBefore w:val=\"1\"/></w:tcPr>",
            "<w:tcPr><w:gridAfter w:val=\"1\"/></w:tcPr>",
            "<w:tcPr><w:tcPrChange/></w:tcPr>",
            "<w:ins><w:p/></w:ins>",
        ] {
            let tbl = table(&format!("{properties}{}", paragraph("unchanged")));
            let xml = wrap(&tbl);
            let out = view(&xml);
            assert_eq!(out["complete"], false, "{properties}");
            assert_eq!(out["scan_complete"], true);
            assert!(out["tables"].as_array().unwrap().is_empty());
            assert_eq!(out["omitted_tables_observed"], 1);
            assert_eq!(out["omissions"][0]["reason"], "unsupported_table_semantics");
            assert_eq!(slice(&xml, &out["omissions"][0]["source_range"]), tbl);
        }
    }

    #[test]
    fn docx_ranges_suppress_nested_alternate_and_remapped_tables_then_resume_siblings() {
        let valid = table(&paragraph("valid"));
        for unsupported in [
            table(&table(&paragraph("inner"))),
            table(
                "<mc:AlternateContent xmlns:mc=\"http://schemas.openxmlformats.org/markup-compatibility/2006\"><mc:Choice><w:p/></mc:Choice></mc:AlternateContent>",
            ),
            table("<w:p xmlns:w=\"urn:foreign\"><w:r><w:t>foreign</w:t></w:r></w:p>"),
            format!("<w:sdt>{valid}</w:sdt>"),
            table(
                "<w:p><w:r><w:t x:flag=\"1\" xmlns:x=\"urn:foreign\">foreign attribute</w:t></w:r></w:p>",
            ),
        ] {
            let xml = wrap(&format!("{unsupported}{valid}"));
            let out = view(&xml);
            assert_eq!(out["complete"], false);
            assert_eq!(out["scan_complete"], true);
            assert_eq!(out["tables"].as_array().unwrap().len(), 1);
            assert_eq!(slice(&xml, &out["tables"][0]["source_range"]), valid);
            assert_eq!(out["omitted_tables_observed"], 1);
        }
    }

    #[test]
    fn docx_ranges_report_malformed_dtd_entity_and_declaration_boundaries() {
        for xml in [
            format!(
                "<!DOCTYPE w:document [<!ENTITY x SYSTEM \"file:///never-read\">]>{}",
                wrap(&table(&paragraph("&x;")))
            ),
            wrap(&table(&paragraph("&not_declared;"))),
            wrap(&table(&paragraph("&#0;"))),
            wrap("<w:tbl><w:tr></w:tbl>"),
            format!("{}{}", wrap(""), wrap("")),
            format!("<?xml version=\"1.0\" encoding=\"UTF-16\"?>{}", wrap("")),
            "<w:document><w:body/></w:document>".into(),
            wrap("<w:tbl bad:attribute=\"x\"/>"),
            format!("\u{feff}\u{feff}{}", wrap("")),
        ] {
            let out = view(&xml);
            assert_eq!(out["complete"], false, "{xml}");
            assert_eq!(out["scan_complete"], false);
            assert!(!out["omissions"].as_array().unwrap().is_empty());
            assert_eq!(
                out["entry_sha256"],
                hex::encode(Sha256::digest(xml.as_bytes()))
            );
        }
    }

    #[test]
    fn docx_ranges_keep_omission_totals_after_diagnostic_cap() {
        let unsupported = table("<w:tcPr><w:vMerge/></w:tcPr><w:p/>");
        let xml = wrap(&unsupported.repeat(65));
        let out = view(&xml);
        assert_eq!(out["complete"], false);
        assert_eq!(out["scan_complete"], true);
        assert_eq!(out["omitted_tables_observed"], 65);
        assert_eq!(out["omissions"].as_array().unwrap().len(), 64);
        assert_eq!(out["omissions_limited"], true);
        assert!(out["tables"].as_array().unwrap().is_empty());
    }

    #[test]
    fn docx_ranges_retain_prior_ranges_but_never_claim_a_complete_malformed_document() {
        let good = table(&paragraph("prior"));
        for suffix in ["<![CDATA[tail]]>", "<w:document>", "&amp;"] {
            let xml = format!("{}{suffix}", wrap(&good));
            let out = view(&xml);
            assert_eq!(out["complete"], false);
            assert_eq!(out["scan_complete"], false);
            assert_eq!(out["tables"].as_array().unwrap().len(), 1);
            assert_eq!(slice(&xml, &out["tables"][0]["source_range"]), good);
        }
        let cdata = table("<w:p><w:r><w:t><![CDATA[raw]]></w:t></w:r></w:p>");
        let xml = wrap(&format!("{cdata}{good}"));
        let out = view(&xml);
        assert_eq!(out["complete"], false);
        assert_eq!(out["scan_complete"], true);
        assert_eq!(out["omitted_tables_observed"], 1);
        assert_eq!(out["tables"].as_array().unwrap().len(), 1);
        assert_eq!(out["omissions"][0]["reason"], "unsupported_cdata");
        let illegal = wrap("<![CDATA[\u{b}]]>");
        assert_eq!(view(&illegal)["scan_complete"], false);
        let opaque = view(&wrap("<![CDATA[non-table content]]>"));
        assert_eq!(opaque["complete"], true);
        assert_eq!(opaque["scan_complete"], true);
        let malformed = "<w:tbl><w:tr></w:tbl>";
        for prefix in ["", "\u{feff}"] {
            let xml = format!("{prefix}{}", wrap(&format!("{good}{malformed}{good}")));
            let out = view(&xml);
            assert_eq!(out["complete"], false);
            assert_eq!(out["scan_complete"], false);
            assert_eq!(out["tables"].as_array().unwrap().len(), 1);
            assert_eq!(slice(&xml, &out["tables"][0]["source_range"]), good);
            assert_eq!(out["omissions"][0]["scope"], "entry_tail");
            assert_eq!(
                out["omissions"][0]["source_range"][0],
                xml.find(malformed).unwrap()
            );
            assert_eq!(out["omissions"][0]["source_range"][1], xml.len());
        }
    }

    #[test]
    fn docx_ranges_apply_independent_work_and_structure_limits_without_partial_tables() {
        let xml = wrap(&table(&format!("{}{}", paragraph("one"), paragraph("two"))));
        for limits in [
            Limits {
                entry_bytes: 8,
                ..LIMITS
            },
            Limits {
                events: 4,
                ..LIMITS
            },
            Limits { depth: 3, ..LIMITS },
            Limits {
                tables: 0,
                ..LIMITS
            },
            Limits { rows: 0, ..LIMITS },
            Limits { cells: 0, ..LIMITS },
            Limits {
                paragraphs: 1,
                ..LIMITS
            },
        ] {
            let out = project_with_limits(&xml, SOURCE, 123, limits);
            assert_eq!(out["complete"], false);
            assert!(out["tables"].as_array().unwrap().is_empty());
            assert!(!out["omissions"].as_array().unwrap().is_empty());
        }
        for prefix in ["", "\u{feff}"] {
            let xml = format!("{prefix}{xml}");
            let out = project_with_limits(
                &xml,
                SOURCE,
                123,
                Limits {
                    events: 1,
                    ..LIMITS
                },
            );
            assert_eq!(out["omissions"][0]["reason"], "event_limit");
            assert_eq!(
                out["omissions"][0]["source_range"][0],
                xml.find("<w:body>").unwrap()
            );
            assert_eq!(out["omissions"][0]["source_range"][1], xml.len());
        }
    }

    #[test]
    fn docx_ranges_cap_actual_serialized_metadata_including_source_binding() {
        let xml = wrap(&table(&paragraph("x").repeat(100)));
        let out = project_with_limits(
            &xml,
            SOURCE,
            123,
            Limits {
                metadata_bytes: 1_536,
                ..LIMITS
            },
        );
        assert_eq!(out["complete"], false);
        assert_eq!(out["scan_complete"], true);
        assert_eq!(out["omitted_tables_observed"], 1);
        assert!(out["tables"].as_array().unwrap().is_empty());
        assert!(
            out["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value["reason"] == "metadata_limit")
        );
        assert!(serde_json::to_vec(&out).unwrap().len() <= 1_536);
        assert_eq!(out["source_document"]["sha256"], SOURCE);
        let unsupported = table("<w:tcPr><w:vMerge/></w:tcPr><w:p/>");
        let xml = wrap(&format!(
            "{}{}",
            unsupported.repeat(12),
            table(&paragraph("x").repeat(100))
        ));
        let out = project_with_limits(
            &xml,
            SOURCE,
            123,
            Limits {
                metadata_bytes: 1_536,
                ..LIMITS
            },
        );
        assert_eq!(out["complete"], false);
        assert_eq!(out["scan_complete"], true);
        assert_eq!(out["omitted_tables_observed"], 13);
        assert_eq!(out["omissions_limited"], true);
        assert!(out["tables"].as_array().unwrap().is_empty());
        assert_eq!(out["omissions"][0]["reason"], "metadata_limit");
        assert!(serde_json::to_vec(&out).unwrap().len() <= 1_536);
    }

    #[test]
    fn docx_sections_bind_property_containers_without_inventing_layout_or_implicit_sections() {
        let intermediate = "<w:sectPr><w:pgSz w:w=\"100\"/></w:sectPr>";
        let final_props = "<w:sectPr/>";
        let body = format!(
            "<w:p><w:pPr>{intermediate}</w:pPr><w:r><w:t>Grüße</w:t></w:r></w:p>{final_props}"
        );
        for prefix in ["", "\u{feff}"] {
            let xml = format!("{prefix}{}", wrap(&body));
            let out = view(&xml);
            assert_eq!(out["schema"], "neoth.document-structure.v3");
            assert_eq!(out["complete"], true);
            let sections = &out["section_properties"];
            assert_eq!(sections["complete"], true);
            let ranges = sections["ranges"].as_array().unwrap();
            assert_eq!(ranges.len(), 2);
            assert_eq!(ranges[0]["context"], "paragraph_properties");
            assert_eq!(ranges[1]["context"], "body");
            assert_eq!(slice(&xml, &ranges[0]["source_range"]), intermediate);
            assert_eq!(slice(&xml, &ranges[1]["source_range"]), final_props);
            crate::memory::document_structure::DocumentStructure::from_value(&out).unwrap();
        }
        let out = view(&wrap(&paragraph("plain")));
        assert_eq!(out["section_properties"]["complete"], true);
        assert!(
            out["section_properties"]["ranges"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn docx_sections_omit_nested_revised_foreign_and_wrong_context_containers_whole() {
        for invalid in [
            "<w:sectPr><w:sectPr/></w:sectPr>",
            "<w:sectPr><w:sectPrChange/></w:sectPr>",
            "<w:sectPr xmlns:x=\"urn:foreign\"><x:setting/></w:sectPr>",
            "<w:sectPr xmlns:x=\"urn:foreign\" x:setting=\"1\"/>",
            "<w:p><w:sectPr/></w:p>",
            "<w:sectPr>unmodeled text</w:sectPr>",
        ] {
            let xml = wrap(&format!("{invalid}<w:sectPr/>"));
            let out = view(&xml);
            let sections = &out["section_properties"];
            assert_eq!(out["scan_complete"], true, "{invalid}");
            assert_eq!(out["complete"], false, "{invalid}");
            assert_eq!(sections["omitted_observed"], 1, "{invalid}");
            assert_eq!(sections["ranges"].as_array().unwrap().len(), 1);
            assert_eq!(
                slice(&xml, &sections["ranges"][0]["source_range"]),
                "<w:sectPr/>"
            );
            crate::memory::document_structure::DocumentStructure::from_value(&out).unwrap();
        }
    }

    #[test]
    fn docx_sections_preserve_bounded_counts_and_never_complete_an_interrupted_container() {
        let xml = wrap(&"<w:sectPr/>".repeat(257));
        let out = view(&xml);
        assert_eq!(
            out["section_properties"]["ranges"]
                .as_array()
                .unwrap()
                .len(),
            256
        );
        assert_eq!(out["section_properties"]["omitted_observed"], 1);
        assert_eq!(out["complete"], false);
        let xml = wrap(&"<w:p><w:sectPr/></w:p>".repeat(65));
        let out = view(&xml);
        assert_eq!(
            out["section_properties"]["omissions"]
                .as_array()
                .unwrap()
                .len(),
            64
        );
        assert_eq!(out["section_properties"]["omitted_observed"], 65);
        assert_eq!(out["section_properties"]["omissions_limited"], true);
        let xml = format!(
            "<w:document xmlns:w=\"{}\"><w:body><w:sectPr>",
            std::str::from_utf8(WORD).unwrap()
        );
        let out = view(&xml);
        assert_eq!(out["scan_complete"], false);
        assert_eq!(out["section_properties"]["complete"], false);
        assert_eq!(out["section_properties"]["omitted_observed"], 1);
        assert_eq!(
            out["section_properties"]["omissions"][0]["source_range"][1],
            xml.len()
        );
        assert!(
            out["section_properties"]["ranges"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        crate::memory::document_structure::DocumentStructure::from_value(&out).unwrap();
    }

    #[test]
    fn docx_sections_share_the_actual_serialized_metadata_limit_with_tables() {
        let xml = wrap(&"<w:sectPr/>".repeat(100));
        let out = project_with_limits(
            &xml,
            SOURCE,
            123,
            Limits {
                metadata_bytes: 1_536,
                ..LIMITS
            },
        );
        assert_eq!(out["scan_complete"], true);
        assert_eq!(out["complete"], false);
        assert_eq!(out["section_properties"]["complete"], false);
        assert_eq!(out["section_properties"]["omitted_observed"], 100);
        assert!(
            out["section_properties"]["ranges"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            out["section_properties"]["omissions"][0]["reason"],
            "metadata_limit"
        );
        let table_only = wrap(&table(&paragraph("x").repeat(100)));
        let table_out = project_with_limits(
            &table_only,
            SOURCE,
            123,
            Limits {
                metadata_bytes: 1_536,
                ..LIMITS
            },
        );
        assert_eq!(table_out["complete"], false);
        assert_eq!(table_out["section_properties"]["omitted_observed"], 0);
        assert_eq!(
            table_out["section_properties"]["omissions"][0]["reason"],
            "metadata_limit"
        );
        crate::memory::document_structure::DocumentStructure::from_value(&table_out).unwrap();
        assert!(serde_json::to_vec(&out).unwrap().len() <= 1_536);
        crate::memory::document_structure::DocumentStructure::from_value(&out).unwrap();
    }

    fn numbered(properties: &str) -> String {
        format!(
            "<w:p><w:pPr><w:numPr>{properties}</w:numPr></w:pPr><w:r><w:t>item</w:t></w:r></w:p>"
        )
    }
    fn checked_numbering(xml: &str) -> Value {
        let value = view(xml);
        crate::memory::document_structure::DocumentStructure::from_value(&value).unwrap();
        value
    }
    #[test]
    fn docx_numbering_binds_exact_physical_ranges_without_inventing_labels() {
        let properties = "<w:ilvl w:val=\"2\"/><w:numId w:val=\"17\"/>";
        let first = numbered(properties);
        let removal = numbered("<w:numId w:val=\"0\"/>");
        let xml = wrap(&format!("{first}{}", table(&removal)));
        let value = checked_numbering(&xml);
        assert_eq!(value["schema"], "neoth.document-structure.v3");
        assert_eq!(value["complete"], true);
        let records = value["numbering_properties"]["records"].as_array().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(slice(&xml, &records[0]["paragraph_source_range"]), first);
        assert_eq!(
            slice(&xml, &records[0]["numbering_properties_source_range"]),
            format!("<w:numPr>{properties}</w:numPr>")
        );
        assert_eq!(records[0]["num_id"], 17);
        assert_eq!(records[0]["level"], 2);
        assert_eq!(records[0]["kind"], "numbering_reference");
        assert_eq!(records[1]["kind"], "numbering_removed");
        assert!(records[1]["level"].is_null());
        assert!(records[0].get("rendered_label").is_none());
        assert!(records[0].get("resolved_definition").is_none());
    }
    #[test]
    fn docx_numbering_resolves_alias_default_strict_namespaces_and_attribute_entities() {
        for namespace in [WORD, STRICT_WORD] {
            let namespace = std::str::from_utf8(namespace).unwrap();
            let body = numbered("<w:numId w:val=\"&#49;7\"/>");
            for (root, xmlns, body) in [
                (
                    "q:",
                    format!("xmlns:q=\"{namespace}\""),
                    body.replace("w:", "q:"),
                ),
                (
                    "",
                    format!("xmlns=\"{namespace}\" xmlns:n=\"{namespace}\""),
                    body.replace("w:val", "n:val").replace("w:", ""),
                ),
            ] {
                let xml = format!(
                    "\u{feff}<{root}document {xmlns}><{root}body>{body}</{root}body></{root}document>"
                );
                let value = checked_numbering(&xml);
                assert_eq!(value["numbering_properties"]["complete"], true);
                let record = &value["numbering_properties"]["records"][0];
                assert_eq!(record["num_id"], 17);
                assert!(record["level"].is_null());
                assert_eq!(slice(&xml, &record["paragraph_source_range"]), body);
            }
        }
    }
    #[test]
    fn docx_numbering_rejects_ambiguous_values_attributes_and_property_content_whole() {
        let alias = std::str::from_utf8(WORD).unwrap();
        let duplicate_alias = format!("<w:numId xmlns:x=\"{alias}\" w:val=\"2\" x:val=\"2\"/>");
        for properties in [
            "",
            "<w:numId/>",
            "<w:numId w:val=\"\"/>",
            "<w:numId w:val=\"-1\"/>",
            "<w:numId w:val=\"4294967296\"/>",
            "<w:numId val=\"2\"/>",
            "<w:numId w:val=\"2\" w:other=\"1\"/>",
            "<w:numId w:val=\"2\"/><w:numId w:val=\"2\"/>",
            "<w:ilvl w:val=\"9\"/><w:numId w:val=\"2\"/>",
            "<w:ilvl w:val=\"0\"/><w:ilvl w:val=\"0\"/><w:numId w:val=\"2\"/>",
            "<w:numId w:val=\"2\"><w:other/></w:numId>",
            "<w:numId w:val=\"2\"/><w:numberingChange/>",
            "<w:numId w:val=\"2\"/><w:ins/>",
            "<w:numId w:val=\"2\"/>unexpected",
            "<w:numId w:val=\"2\"/><![CDATA[unexpected]]>",
            "<w:numId w:val=\"2\"/>&amp;",
            "<w:numId w:val=\"2\"/><x:other xmlns:x=\"urn:foreign\"/>",
            &duplicate_alias,
        ] {
            let bad = numbered(properties);
            let good = numbered("<w:numId w:val=\"3\"/>");
            let xml = wrap(&format!("{bad}{good}"));
            let value = checked_numbering(&xml);
            let numbering = &value["numbering_properties"];
            assert_eq!(numbering["complete"], false, "{properties}");
            assert_eq!(numbering["omitted_observed"], 1, "{properties}");
            assert_eq!(
                numbering["records"].as_array().unwrap().len(),
                1,
                "{properties}"
            );
            assert_eq!(numbering["records"][0]["num_id"], 3);
            assert_eq!(slice(&xml, &numbering["omissions"][0]["source_range"]), bad);
        }
        let bad = "<w:p><w:pPr><w:numPr w:val=\"2\"><w:numId w:val=\"2\"/></w:numPr></w:pPr></w:p>";
        let value = checked_numbering(&wrap(bad));
        assert_eq!(value["numbering_properties"]["omitted_observed"], 1);
    }
    #[test]
    fn docx_numbering_nested_order_and_later_properties_omit_one_outer_paragraph() {
        let props = "<w:pPr><w:numPr><w:numId w:val=\"1\"/></w:numPr></w:pPr>";
        let nested = numbered("<w:numId w:val=\"2\"/>");
        for inner in [
            format!("{nested}{props}"),
            format!("{props}{nested}"),
            format!("{props}{props}"),
        ] {
            let bad = format!("<w:p>{inner}</w:p>");
            let xml = wrap(&format!("{bad}{}", numbered("<w:numId w:val=\"3\"/>")));
            let value = checked_numbering(&xml);
            let numbering = &value["numbering_properties"];
            assert_eq!(numbering["omitted_observed"], 1);
            assert_eq!(numbering["omissions"].as_array().unwrap().len(), 1);
            assert_eq!(slice(&xml, &numbering["omissions"][0]["source_range"]), bad);
            assert_eq!(numbering["records"].as_array().unwrap().len(), 1);
            assert_eq!(numbering["records"][0]["num_id"], 3);
        }
        let outside = "<w:numPr><w:numId w:val=\"1\"/></w:numPr>";
        let value = checked_numbering(&wrap(outside));
        assert_eq!(value["numbering_properties"]["omitted_observed"], 1);
        assert!(
            value["numbering_properties"]["records"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn docx_numbering_incomplete_table_rewinds_previously_emitted_paragraphs() {
        let good = numbered("<w:numId w:val=\"1\"/>");
        let within = numbered("<w:numId w:val=\"2\"/>");
        let xml = wrap(&format!("{good}<w:tbl><w:tr><w:tc>{within}{within}</w:tr>"));
        let value = checked_numbering(&xml);
        assert_eq!(value["scan_complete"], false);
        let numbering = &value["numbering_properties"];
        assert_eq!(numbering["records"].as_array().unwrap().len(), 1);
        assert_eq!(numbering["records"][0]["num_id"], 1);
        assert_eq!(numbering["omitted_observed"], 2);
        assert!(
            numbering["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .all(|item| item["reason"] == "incomplete_entry_tail")
        );
        let xml = wrap("<w:p><w:pPr><w:numPr><w:numId w:val=\"1\"/></w:numPr></w:pPr>");
        let value = checked_numbering(&xml);
        assert_eq!(value["numbering_properties"]["omitted_observed"], 1);
        assert!(
            value["numbering_properties"]["records"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn docx_numbering_bounds_records_details_and_shared_serialized_metadata() {
        let xml = wrap(&numbered("<w:numId w:val=\"1\"/>").repeat(257));
        let value = checked_numbering(&xml);
        assert_eq!(
            value["numbering_properties"]["records"]
                .as_array()
                .unwrap()
                .len(),
            256
        );
        assert_eq!(value["numbering_properties"]["omitted_observed"], 1);
        assert_eq!(value["numbering_properties"]["omissions_limited"], false);
        let compact = project_with_limits(
            &xml,
            SOURCE,
            123,
            Limits {
                metadata_bytes: 1_536,
                ..LIMITS
            },
        );
        crate::memory::document_structure::DocumentStructure::from_value(&compact).unwrap();
        assert!(serde_json::to_vec(&compact).unwrap().len() <= 1_536);
        assert!(
            compact["numbering_properties"]["records"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(compact["numbering_properties"]["omitted_observed"], 257);
        assert_eq!(
            compact["numbering_properties"]["omissions"][0]["reason"],
            "metadata_limit"
        );
        let xml = wrap(&numbered("<w:numId/>").repeat(65));
        let value = checked_numbering(&xml);
        assert_eq!(value["numbering_properties"]["omitted_observed"], 65);
        assert_eq!(
            value["numbering_properties"]["omissions"]
                .as_array()
                .unwrap()
                .len(),
            64
        );
        assert_eq!(value["numbering_properties"]["omissions_limited"], true);
    }
}
