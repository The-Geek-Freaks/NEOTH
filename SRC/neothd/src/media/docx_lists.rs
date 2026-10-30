//! Physical explicit numbering references; no style, list-layout, or ordinal inference.
use super::Frame;
use serde::Serialize;

const MAX_RECORDS: usize = 256;
const MAX_OMISSIONS: usize = 64;

#[derive(Clone, Copy, Debug)]
pub(super) enum Val {
    Absent,
    Number(u32),
    Invalid,
}

#[derive(Debug, Serialize)]
pub(super) struct Record {
    pub paragraph_source_range: [usize; 2],
    pub numbering_properties_source_range: [usize; 2],
    pub num_id: u32,
    pub level: Option<u8>,
    pub kind: &'static str,
}

#[derive(Debug, Serialize)]
pub(super) struct Omission {
    pub reason: &'static str,
    pub source_range: [usize; 2],
}

#[derive(Debug, Serialize)]
pub(super) struct Projection {
    pub complete: bool,
    pub records: Vec<Record>,
    pub omitted_observed: usize,
    pub omissions_limited: bool,
    pub omissions: Vec<Omission>,
}

impl Projection {
    // At most 256 converted records plus 64 retained omission details.
    pub(super) fn discard_from(&mut self, entry_tail_start: usize) {
        let mut retained = Vec::with_capacity(self.records.len());
        for record in self.records.drain(..) {
            if record.paragraph_source_range[1] > entry_tail_start {
                self.omitted_observed += 1;
                self.omissions.push(Omission {
                    reason: "incomplete_entry_tail",
                    source_range: record.paragraph_source_range,
                });
            } else {
                retained.push(record);
            }
        }
        self.records = retained;
        self.omissions.sort_by_key(|omission| omission.source_range);
        if self.omissions.len() > MAX_OMISSIONS {
            self.omissions.truncate(MAX_OMISSIONS);
            self.omissions_limited = true;
        }
        self.complete = false;
    }

    pub(super) fn discard_for_metadata_limit(&mut self, entry_bytes: usize) {
        self.omitted_observed += self.records.len();
        self.records.clear();
        self.omissions.clear();
        self.omissions.push(Omission {
            reason: "metadata_limit",
            source_range: [0, entry_bytes],
        });
        self.complete = false;
        self.omissions_limited = true;
    }
}

struct Candidate {
    paragraph_depth: Option<usize>,
    paragraph_start: usize,
    properties_depth: usize,
    properties_start: usize,
    properties_end: Option<usize>,
    num_id_seen: bool,
    num_id: Option<u32>,
    level_seen: bool,
    level: Option<u8>,
    rejected: Option<&'static str>,
}

impl Candidate {
    fn reject(&mut self, reason: &'static str) {
        self.rejected.get_or_insert(reason);
    }
}

#[derive(Default)]
pub(super) struct Projector {
    pending: Option<Candidate>,
    property_active_depth: Option<usize>,
    tainted_paragraphs: Vec<usize>,
    records: Vec<Record>,
    omitted_observed: usize,
    omissions_limited: bool,
    omissions: Vec<Omission>,
}

fn path_is(stack: &[Frame], names: &[&[u8]]) -> bool {
    stack.len() == names.len() && stack.iter().zip(names).all(|(frame, name)| frame.is(name))
}

fn supported_parent_path(stack: &[Frame]) -> bool {
    path_is(stack, &[b"document", b"body", b"p", b"pPr"])
        || path_is(
            stack,
            &[b"document", b"body", b"tbl", b"tr", b"tc", b"p", b"pPr"],
        )
}

impl Projector {
    /// The scanner has pushed the new frame; current depth is stack.len().
    /// Attributes must already be bounded, namespace-resolved, and checked.
    pub(super) fn begin(
        &mut self,
        stack: &[Frame],
        start: usize,
        value: Val,
        attributes_supported: bool,
    ) {
        let Some(current) = stack.last() else { return };
        let depth = stack.len();
        // Remember nested paragraphs even when their numPr appears later.
        // Only open paragraph depths are retained; the scanner caps depth at128.
        if current.is(b"p") {
            let mut nested = false;
            for (index, frame) in stack[..depth - 1].iter().enumerate() {
                if frame.is(b"p") {
                    nested = true;
                    let ancestor_depth = index + 1;
                    if !self.tainted_paragraphs.contains(&ancestor_depth) {
                        self.tainted_paragraphs.push(ancestor_depth);
                    }
                }
            }
            if nested {
                self.tainted_paragraphs.push(depth);
            }
        }
        if let Some(candidate) = self.pending.as_mut()
            && current.is(b"p")
            && candidate
                .paragraph_depth
                .is_some_and(|parent| depth > parent)
        {
            candidate.reject("nested_numbered_paragraph");
        }
        if let Some(property_depth) = self.property_active_depth {
            let Some(candidate) = self.pending.as_mut() else {
                return;
            };
            if depth != property_depth + 1 {
                candidate.reject("unsupported_numbering_properties");
                return;
            }
            if !attributes_supported {
                candidate.reject("unsupported_numbering_attributes");
            }
            if current.is(b"numId") {
                if candidate.num_id_seen {
                    candidate.reject("duplicate_num_id");
                }
                candidate.num_id_seen = true;
                match value {
                    Val::Number(number) => candidate.num_id = Some(number),
                    Val::Absent | Val::Invalid => candidate.reject("invalid_num_id"),
                }
            } else if current.is(b"ilvl") {
                if candidate.level_seen {
                    candidate.reject("duplicate_level");
                }
                candidate.level_seen = true;
                match value {
                    Val::Number(number) if number <= 8 => {
                        candidate.level = Some(number as u8);
                    }
                    Val::Number(_) => candidate.reject("unsupported_numbering_level"),
                    Val::Absent | Val::Invalid => {
                        candidate.reject("invalid_level");
                    }
                }
            } else {
                candidate.reject("unsupported_numbering_properties");
            }
            return;
        }
        if !current.is(b"numPr") {
            return;
        }
        // Delay publication to paragraph end: a later sibling must invalidate
        // the same candidate rather than create another partial paragraph.
        if let Some(candidate) = self.pending.as_mut() {
            candidate.reject("duplicate_numbering_properties");
            self.property_active_depth = Some(depth);
            return;
        }
        let ancestors = &stack[..depth - 1];
        let paragraph = ancestors
            .iter()
            .enumerate()
            .find(|(_, frame)| frame.is(b"p"));
        let (paragraph_depth, paragraph_start) = match paragraph {
            Some((index, frame)) => (Some(index + 1), frame.start),
            None => (None, start),
        };
        let mut candidate = Candidate {
            paragraph_depth,
            paragraph_start,
            properties_depth: depth,
            properties_start: start,
            properties_end: None,
            num_id_seen: false,
            num_id: None,
            level_seen: false,
            level: None,
            rejected: None,
        };
        if paragraph_depth.is_some_and(|depth| self.tainted_paragraphs.contains(&depth)) {
            candidate.reject("nested_numbered_paragraph");
        }
        if !supported_parent_path(ancestors) {
            candidate.reject("unsupported_numbering_context");
        }
        if !attributes_supported {
            candidate.reject("unsupported_numbering_attributes");
        }
        self.pending = Some(candidate);
        self.property_active_depth = Some(depth);
    }

    /// Called before the scanner pops the frame at this one-based depth.
    pub(super) fn end(&mut self, depth: usize, end: usize) {
        self.tainted_paragraphs.retain(|open| *open != depth);
        if self.property_active_depth == Some(depth) {
            self.property_active_depth = None;
            if let Some(candidate) = self.pending.as_mut()
                && candidate.properties_depth == depth
                && candidate.properties_end.is_none()
            {
                candidate.properties_end = Some(end);
                if !candidate.num_id_seen {
                    candidate.reject("missing_num_id");
                }
            }
            if self
                .pending
                .as_ref()
                .is_some_and(|c| c.paragraph_depth.is_none())
            {
                self.finalize(end);
                return;
            }
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|c| c.paragraph_depth == Some(depth))
        {
            self.finalize(end);
        }
    }

    /// The scanner calls this for non-whitespace text, CDATA, entity or
    /// unsupported attributes. Ordinary paragraph content is outside numPr.
    pub(super) fn reject_property_content(&mut self, reason: &'static str) {
        if self.property_active_depth.is_some()
            && let Some(candidate) = self.pending.as_mut()
        {
            candidate.reject(reason);
        }
    }

    fn omit(&mut self, reason: &'static str, range: [usize; 2]) {
        self.omitted_observed += 1;
        if self.omissions.len() < MAX_OMISSIONS {
            self.omissions.push(Omission {
                reason,
                source_range: range,
            });
        } else {
            self.omissions_limited = true;
        }
    }

    fn finalize(&mut self, end: usize) {
        let Some(candidate) = self.pending.take() else {
            return;
        };
        self.property_active_depth = None;
        if let Some(reason) = candidate.rejected {
            self.omit(reason, [candidate.paragraph_start, end]);
            return;
        }
        let (Some(properties_end), Some(num_id)) = (candidate.properties_end, candidate.num_id)
        else {
            self.omit(
                "incomplete_numbering_properties",
                [candidate.paragraph_start, end],
            );
            return;
        };
        if self.records.len() >= MAX_RECORDS {
            self.omit("record_limit", [candidate.paragraph_start, end]);
            return;
        }
        self.records.push(Record {
            paragraph_source_range: [candidate.paragraph_start, end],
            numbering_properties_source_range: [candidate.properties_start, properties_end],
            num_id,
            level: candidate.level,
            kind: if num_id == 0 {
                "numbering_removed"
            } else {
                "numbering_reference"
            },
        });
    }

    pub(super) fn finish(mut self, scan_complete: bool, entry_bytes: usize) -> Projection {
        if let Some(candidate) = self.pending.take() {
            self.omit(
                "incomplete_numbering_properties",
                [candidate.paragraph_start, entry_bytes],
            );
        }
        Projection {
            complete: scan_complete && self.omitted_observed == 0,
            records: self.records,
            omitted_observed: self.omitted_observed,
            omissions_limited: self.omissions_limited,
            omissions: self.omissions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Harness {
        projector: Projector,
        stack: Vec<Frame>,
    }

    impl Harness {
        fn open(&mut self, name: &[u8], start: usize, value: Val) {
            self.stack.push(Frame {
                local: name.to_vec(),
                word: true,
                properties: false,
                start,
            });
            self.projector.begin(&self.stack, start, value, true);
        }

        fn close(&mut self, end: usize) {
            self.projector.end(self.stack.len(), end);
            self.stack.pop().unwrap();
        }

        fn document(&mut self) {
            self.open(b"document", 0, Val::Absent);
            self.open(b"body", 1, Val::Absent);
        }

        fn num_pr(&mut self, start: usize, end: usize, id: u32) {
            self.open(b"pPr", start, Val::Absent);
            self.open(b"numPr", start + 1, Val::Absent);
            self.open(b"numId", start + 2, Val::Number(id));
            self.close(start + 3);
            self.close(end - 1);
            self.close(end);
        }

        fn finish(mut self, end: usize) -> Projection {
            self.close(end - 1);
            self.close(end);
            self.projector.finish(true, end)
        }
    }

    #[test]
    fn nested_paragraph_before_or_after_properties_omits_outer_paragraph() {
        let mut h = Harness::default();
        h.document();
        h.open(b"p", 10, Val::Absent);
        h.open(b"p", 11, Val::Absent);
        h.close(12);
        h.num_pr(13, 18, 1);
        h.close(20);
        h.open(b"p", 30, Val::Absent);
        h.num_pr(31, 36, 2);
        h.open(b"p", 37, Val::Absent);
        h.close(38);
        h.close(40);
        h.open(b"p", 50, Val::Absent);
        h.num_pr(51, 56, 3);
        h.close(60);
        let projection = h.finish(70);
        assert!(!projection.complete);
        assert_eq!(projection.omitted_observed, 2);
        assert_eq!(projection.omissions.len(), 2);
        assert_eq!(projection.omissions[0].source_range, [10, 20]);
        assert_eq!(projection.omissions[1].source_range, [30, 40]);
        assert_eq!(projection.records.len(), 1);
        assert_eq!(projection.records[0].paragraph_source_range, [50, 60]);
        assert_eq!(
            projection.records[0].numbering_properties_source_range,
            [52, 55]
        );
        assert_eq!(projection.records[0].num_id, 3);
    }

    #[test]
    fn later_sibling_invalidates_pending_paragraph_without_leaking_state() {
        let mut h = Harness::default();
        h.document();
        h.open(b"p", 10, Val::Absent);
        h.num_pr(11, 16, 4);
        assert!(h.projector.records.is_empty());
        h.num_pr(17, 22, 5);
        assert!(h.projector.records.is_empty());
        h.close(25);
        h.open(b"p", 30, Val::Absent);
        h.num_pr(31, 36, 0);
        h.close(40);
        let projection = h.finish(50);
        assert_eq!(projection.omitted_observed, 1);
        assert_eq!(projection.omissions[0].source_range, [10, 25]);
        assert_eq!(projection.records.len(), 1);
        let record = &projection.records[0];
        assert_eq!(record.paragraph_source_range, [30, 40]);
        assert_eq!(record.num_id, 0);
        assert_eq!(record.kind, "numbering_removed");
        assert_eq!(record.level, None);
    }

    #[test]
    fn record_limit_and_metadata_discard_count_all_omitted_paragraphs() {
        let mut h = Harness::default();
        h.document();
        for index in 0..257 {
            let start = 10 + index * 10;
            h.open(b"p", start, Val::Absent);
            h.num_pr(start + 1, start + 6, 7);
            h.close(start + 8);
        }
        let mut projection = h.finish(3000);
        assert_eq!(projection.records.len(), 256);
        assert_eq!(projection.omitted_observed, 1);
        assert_eq!(projection.omissions.len(), 1);
        assert!(!projection.omissions_limited);
        assert!(!projection.complete);
        projection.discard_for_metadata_limit(3000);
        assert!(projection.records.is_empty());
        assert_eq!(projection.omitted_observed, 257);
        assert_eq!(projection.omissions.len(), 1);
        assert_eq!(projection.omissions[0].reason, "metadata_limit");
        assert_eq!(projection.omissions[0].source_range, [0, 3000]);
        assert!(projection.omissions_limited);
        assert!(!projection.complete);
    }
    #[test]
    fn nested_numbering_before_or_after_outer_properties_omits_one_whole_paragraph() {
        for inner_first in [true, false] {
            let mut h = Harness::default();
            h.document();
            h.open(b"p", 10, Val::Absent);
            if !inner_first {
                h.num_pr(11, 16, 1);
            }
            h.open(b"p", 20, Val::Absent);
            h.num_pr(21, 26, 2);
            h.close(30);
            if inner_first {
                h.num_pr(31, 36, 1);
            }
            h.close(40);
            h.open(b"p", 50, Val::Absent);
            h.num_pr(51, 56, 3);
            h.close(60);
            let projection = h.finish(70);
            assert_eq!(projection.omitted_observed, 1);
            assert_eq!(projection.omissions.len(), 1);
            assert_eq!(projection.omissions[0].source_range, [10, 40]);
            assert_eq!(projection.records.len(), 1);
            assert_eq!(projection.records[0].paragraph_source_range, [50, 60]);
            assert_eq!(projection.records[0].num_id, 3);
        }
    }
    #[test]
    fn incomplete_entry_tail_discards_overlapping_records_and_orders_omissions() {
        let mut h = Harness::default();
        h.document();
        for (start, id) in [(10, 1), (30, 2), (50, 3)] {
            h.open(b"p", start, Val::Absent);
            h.num_pr(start + 1, start + 6, id);
            h.close(start + 10);
        }
        let mut projection = h.finish(70);
        projection.discard_from(25);
        assert_eq!(projection.records.len(), 1);
        assert_eq!(projection.records[0].paragraph_source_range, [10, 20]);
        assert_eq!(projection.omitted_observed, 2);
        assert_eq!(projection.omissions.len(), 2);
        assert_eq!(projection.omissions[0].reason, "incomplete_entry_tail");
        assert_eq!(projection.omissions[0].source_range, [30, 40]);
        assert_eq!(projection.omissions[1].source_range, [50, 60]);
        assert!(!projection.omissions_limited);
        assert!(!projection.complete);
    }
}
