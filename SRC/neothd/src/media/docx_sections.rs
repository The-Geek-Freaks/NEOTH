//! Physical section-property containers; no rendered section or page model.
use super::Frame;
use serde::Serialize;

const MAX_RANGES: usize = 256;
const MAX_OMISSIONS: usize = 64;

#[derive(Serialize)]
pub(super) struct Range {
    context: &'static str,
    source_range: [usize; 2],
}

#[derive(Serialize)]
struct Omission {
    reason: &'static str,
    source_range: [usize; 2],
}

#[derive(Serialize)]
pub(super) struct Projection {
    pub(super) complete: bool,
    omitted_observed: usize,
    omissions_limited: bool,
    ranges: Vec<Range>,
    omissions: Vec<Omission>,
}

struct Building {
    depth: usize,
    context: &'static str,
    start: usize,
    reason: Option<&'static str>,
}

pub(super) struct Sections {
    out: Projection,
    building: Option<Building>,
}

impl Sections {
    pub(super) fn new() -> Self {
        Self {
            out: Projection {
                complete: false,
                omitted_observed: 0,
                omissions_limited: false,
                ranges: Vec::new(),
                omissions: Vec::new(),
            },
            building: None,
        }
    }

    pub(super) fn begin(&mut self, stack: &[Frame], start: usize) {
        let Some(frame) = stack.last() else { return };
        if frame.is(b"sectPr") {
            if self.building.is_some() {
                self.reject("nested_section_properties");
                return;
            }
            let body = stack.len() == 3 && stack[0].is(b"document") && stack[1].is(b"body");
            let paragraph = stack.len() == 5
                && stack[0].is(b"document")
                && stack[1].is(b"body")
                && stack[2].is(b"p")
                && stack[3].is(b"pPr");
            self.building = Some(Building {
                depth: stack.len(),
                context: if body { "body" } else { "paragraph_properties" },
                start,
                reason: (!(body || paragraph)).then_some("unsupported_section_context"),
            });
        } else if self.building.is_some() && (!frame.word || frame.is(b"sectPrChange")) {
            self.reject("unsupported_section_semantics");
        }
    }

    pub(super) fn reject(&mut self, reason: &'static str) {
        if let Some(building) = &mut self.building {
            building.reason.get_or_insert(reason);
        }
    }

    fn omit(&mut self, reason: &'static str, range: [usize; 2], count: usize) {
        self.out.omitted_observed += count;
        if self.out.omissions.len() < MAX_OMISSIONS {
            self.out.omissions.push(Omission {
                reason,
                source_range: range,
            });
        } else {
            self.out.omissions_limited = true;
        }
    }

    pub(super) fn end(&mut self, depth: usize, end: usize) {
        if self.building.as_ref().is_none_or(|b| b.depth != depth) {
            return;
        }
        let building = self.building.take().expect("matching section depth");
        let reason = building
            .reason
            .or_else(|| (self.out.ranges.len() >= MAX_RANGES).then_some("section_range_limit"));
        let range = [building.start, end];
        if let Some(reason) = reason {
            self.omit(reason, range, 1);
        } else {
            self.out.ranges.push(Range {
                context: building.context,
                source_range: range,
            });
        }
    }

    pub(super) fn finish(mut self, scan_complete: bool, entry_bytes: usize) -> Projection {
        if let Some(building) = self.building.take() {
            self.omit(
                "incomplete_section_properties",
                [building.start, entry_bytes],
                1,
            );
        }
        self.out.complete = scan_complete && self.out.omitted_observed == 0;
        self.out
    }
}

impl Projection {
    pub(super) fn discard_for_metadata_limit(&mut self, entry_bytes: usize) {
        let count = self.ranges.len();
        self.ranges.clear();
        self.omitted_observed += count;
        self.complete = false;
        self.omissions.clear();
        self.omissions.push(Omission {
            reason: "metadata_limit",
            source_range: [0, entry_bytes],
        });
        self.omissions_limited = true;
    }
}
