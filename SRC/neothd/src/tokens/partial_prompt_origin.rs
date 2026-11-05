//! Partial origin evidence after destructive prompt compaction. Counts only
//! subsequently appended rendered tool blocks; the compacted base is unknown.

use serde::{Deserialize, Serialize};

use super::prompt_attribution::PromptEstimator;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialCoverage {
    PostCompactionAppendsV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PartialWire")]
pub struct PartialPromptOrigin {
    known_tool_result_bytes: u32,
    request_upper_bound: u32,
    coverage: PartialCoverage,
    estimator: PromptEstimator,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialWire {
    known_tool_result_bytes: u32,
    request_upper_bound: u32,
    coverage: PartialCoverage,
    estimator: PromptEstimator,
}

impl TryFrom<PartialWire> for PartialPromptOrigin {
    type Error = &'static str;

    fn try_from(wire: PartialWire) -> Result<Self, Self::Error> {
        Self::new(wire.known_tool_result_bytes, wire.request_upper_bound)
            .map(|mut result| {
                result.coverage = wire.coverage;
                result.estimator = wire.estimator;
                result
            })
    }
}

impl PartialPromptOrigin {
    pub(crate) fn new(known_tool_result_bytes: u32, request_upper_bound: u32) -> Result<Self, &'static str> {
        if known_tool_result_bytes > request_upper_bound {
            return Err("partial tool bytes exceed final request bound");
        }
        Ok(Self {
            known_tool_result_bytes,
            request_upper_bound,
            coverage: PartialCoverage::PostCompactionAppendsV1,
            estimator: PromptEstimator::Utf8ByteUpperBoundV1,
        })
    }

    pub fn known_tool_result_bytes(&self) -> u32 {
        self.known_tool_result_bytes
    }

    pub fn request_upper_bound(&self) -> u32 {
        self.request_upper_bound
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialOriginTotals {
    pub observed_call_count: u64,
    pub known_tool_result_bytes: u64,
    pub request_upper_bound: u64,
}

impl PartialOriginTotals {
    pub(crate) fn try_absorb(&mut self, evidence: PartialPromptOrigin) -> Option<()> {
        let next = Self {
            observed_call_count: self.observed_call_count.checked_add(1)?,
            known_tool_result_bytes: self.known_tool_result_bytes.checked_add(u64::from(evidence.known_tool_result_bytes))?,
            request_upper_bound: self.request_upper_bound.checked_add(u64::from(evidence.request_upper_bound))?,
        };
        *self = next;
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_origin_retains_zero_coverage_and_rejects_invalid_or_overflowing_evidence() {
        let zero = PartialPromptOrigin::new(0, 40).unwrap();
        let wire = serde_json::to_value(zero).unwrap();
        assert_eq!(wire["coverage"], "post_compaction_appends_v1");
        assert_eq!(serde_json::from_value::<PartialPromptOrigin>(wire.clone()).unwrap(), zero);
        for (field, value) in [
            ("known_tool_result_bytes", serde_json::json!(41)),
            ("coverage", serde_json::json!("all_tool_content")),
            ("other_origin_bytes", serde_json::json!(0)),
        ] {
            let mut changed = wire.clone();
            changed[field] = value;
            assert!(serde_json::from_value::<PartialPromptOrigin>(changed).is_err());
        }
        let mut totals = PartialOriginTotals::default();
        totals.try_absorb(zero).unwrap();
        assert_eq!(totals.observed_call_count, 1);
        totals.known_tool_result_bytes = u64::MAX;
        let before = totals.clone();
        assert!(totals.try_absorb(PartialPromptOrigin::new(1, 40).unwrap()).is_none());
        assert_eq!(totals, before);
    }
}
