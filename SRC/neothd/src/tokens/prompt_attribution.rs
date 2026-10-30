//! Content-free estimates of final retained prompt components. These are
//! conservative local bounds, never provider measurements or allocated cost.

use serde::{Deserialize, Serialize};

use super::budget::{BlockItem, count_tokens_upper_bound};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptOrigin {
    System,
    Workflow,
    Skill,
    Retrieval,
    ToolResult,
    User,
    Unattributed,
}

/// V1 counts UTF-8 content bytes plus the existing token-cap envelope reserve.
/// It does not claim to use a model tokenizer. Change the version if the
/// underlying request/message reserve semantics change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptEstimator {
    Utf8ByteUpperBoundV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PromptAttributionWire")]
pub struct PromptAttribution {
    system: u32,
    workflow: u32,
    skill: u32,
    retrieval: u32,
    tool_result: u32,
    user: u32,
    unattributed: u32,
    request_upper_bound: u32,
    envelope_residual: u32,
    estimator: PromptEstimator,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PromptAttributionWire {
    system: u32,
    workflow: u32,
    skill: u32,
    retrieval: u32,
    tool_result: u32,
    user: u32,
    unattributed: u32,
    request_upper_bound: u32,
    envelope_residual: u32,
    estimator: PromptEstimator,
}

impl TryFrom<PromptAttributionWire> for PromptAttribution {
    type Error = &'static str;

    fn try_from(wire: PromptAttributionWire) -> Result<Self, Self::Error> {
        let attribution = Self {
            system: wire.system,
            workflow: wire.workflow,
            skill: wire.skill,
            retrieval: wire.retrieval,
            tool_result: wire.tool_result,
            user: wire.user,
            unattributed: wire.unattributed,
            request_upper_bound: wire.request_upper_bound,
            envelope_residual: wire.envelope_residual,
            estimator: wire.estimator,
        };
        attribution.validate()?;
        Ok(attribution)
    }
}

impl PromptAttribution {
    pub fn from_retained_items(
        items: &[BlockItem],
        request_upper_bound: u32,
    ) -> Result<Self, &'static str> {
        let mut result = Self {
            system: 0,
            workflow: 0,
            skill: 0,
            retrieval: 0,
            tool_result: 0,
            user: 0,
            unattributed: 0,
            request_upper_bound,
            envelope_residual: 0,
            estimator: PromptEstimator::Utf8ByteUpperBoundV1,
        };
        for item in items {
            if item.tokens != count_tokens_upper_bound(&item.content) {
                return Err("retained item estimate does not match UTF-8 byte count");
            }
            let count = match item.prompt_origin.unwrap_or(PromptOrigin::Unattributed) {
                PromptOrigin::System => &mut result.system,
                PromptOrigin::Workflow => &mut result.workflow,
                PromptOrigin::Skill => &mut result.skill,
                PromptOrigin::Retrieval => &mut result.retrieval,
                PromptOrigin::ToolResult => &mut result.tool_result,
                PromptOrigin::User => &mut result.user,
                PromptOrigin::Unattributed => &mut result.unattributed,
            };
            *count = count
                .checked_add(item.tokens)
                .ok_or("prompt component overflow")?;
        }
        let retained_total = result.counts().into_iter().try_fold(0u32, |sum, count| {
            sum.checked_add(count)
                .ok_or("prompt component total overflow")
        })?;
        result.envelope_residual = request_upper_bound
            .checked_sub(retained_total)
            .ok_or("retained components exceed request upper bound")?;
        result.validate()?;
        Ok(result)
    }

    /// Extend proven retained content with bytes actually appended by the loop.
    /// Changed envelope semantics cannot reuse a previous component estimate.
    pub(crate) fn with_appended_tool_results(
        mut self,
        appended_bytes: u32,
        tool_bytes: u32,
        final_request_bound: u32,
    ) -> Result<Self, &'static str> {
        self.validate()?;
        if tool_bytes > appended_bytes {
            return Err("tool bytes exceed appended bytes");
        }
        if final_request_bound.checked_sub(appended_bytes) != Some(self.request_upper_bound) {
            return Err("request envelope changed");
        }
        self.tool_result = self
            .tool_result
            .checked_add(tool_bytes)
            .ok_or("tool result attribution overflow")?;
        self.unattributed = self
            .unattributed
            .checked_add(appended_bytes - tool_bytes)
            .ok_or("unattributed attribution overflow")?;
        self.request_upper_bound = final_request_bound;
        self.validate()?;
        Ok(self)
    }

    /// System, workflow, skill, retrieval, tool result, user, unattributed.
    pub fn counts(&self) -> [u32; 7] {
        [
            self.system,
            self.workflow,
            self.skill,
            self.retrieval,
            self.tool_result,
            self.user,
            self.unattributed,
        ]
    }

    pub fn request_upper_bound(&self) -> u32 {
        self.request_upper_bound
    }
    pub fn envelope_residual(&self) -> u32 {
        self.envelope_residual
    }
    pub fn estimator(&self) -> PromptEstimator {
        self.estimator
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        let total = self
            .counts()
            .into_iter()
            .chain(std::iter::once(self.envelope_residual))
            .try_fold(0u32, |sum, count| {
                sum.checked_add(count)
                    .ok_or("prompt component total overflow")
            })?;
        if total != self.request_upper_bound {
            return Err("prompt components do not match request upper bound");
        }
        Ok(())
    }
}

/// Totals over calls with observed component estimates, not all usage calls.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptComponentTotals {
    pub observed_call_count: u64,
    pub system: u64,
    pub workflow: u64,
    pub skill: u64,
    pub retrieval: u64,
    pub tool_result: u64,
    pub user: u64,
    pub unattributed: u64,
    pub request_upper_bound: u64,
    pub envelope_residual: u64,
}

impl PromptComponentTotals {
    /// Commit all counters together or leave the previous total unchanged.
    pub fn try_absorb(&mut self, value: PromptAttribution) -> Result<(), &'static str> {
        value.validate()?;
        let mut next = *self;
        let counts = value.counts();
        for (target, increment) in [
            (&mut next.observed_call_count, 1),
            (&mut next.system, u64::from(counts[0])),
            (&mut next.workflow, u64::from(counts[1])),
            (&mut next.skill, u64::from(counts[2])),
            (&mut next.retrieval, u64::from(counts[3])),
            (&mut next.tool_result, u64::from(counts[4])),
            (&mut next.user, u64::from(counts[5])),
            (&mut next.unattributed, u64::from(counts[6])),
            (
                &mut next.request_upper_bound,
                u64::from(value.request_upper_bound()),
            ),
            (
                &mut next.envelope_residual,
                u64::from(value.envelope_residual()),
            ),
        ] {
            *target = target
                .checked_add(increment)
                .ok_or("prompt component rollup overflow")?;
        }
        *self = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::budget::{Block, PromptTaxSource};

    #[test]
    fn appended_tool_results_preserve_known_origins_and_utf8_residual() {
        let items = [
            BlockItem::new(Block::A, "policy").with_prompt_origin(PromptOrigin::System),
            BlockItem::new(Block::E, "ä").with_prompt_origin(PromptOrigin::User),
        ];
        let base = PromptAttribution::from_retained_items(&items, 520).unwrap();
        let first_tool = "🦀";
        let first = base
            .with_appended_tool_results(7, u32::try_from(first_tool.len()).unwrap(), 527)
            .unwrap();
        assert_eq!(first.counts(), [6, 0, 0, 0, 4, 2, 3]);
        assert_eq!(first.envelope_residual(), 512);
        let second = first.with_appended_tool_results(2, 0, 529).unwrap();
        assert_eq!(second.counts(), [6, 0, 0, 0, 4, 2, 5]);
        assert_eq!(second, base.with_appended_tool_results(9, 4, 529).unwrap());
        assert_eq!(base.counts(), [6, 0, 0, 0, 0, 2, 0]);
    }

    #[test]
    fn appended_tool_results_reject_invalid_counts_envelope_and_saturation() {
        let base = PromptAttribution::from_retained_items(&[], 512).unwrap();
        assert!(base.with_appended_tool_results(1, 2, 513).is_err());
        assert!(base.with_appended_tool_results(1, 1, 514).is_err());
        assert!(base.with_appended_tool_results(513, 0, 512).is_err());
        let full = PromptAttribution::from_retained_items(&[], u32::MAX).unwrap();
        assert!(full.with_appended_tool_results(1, 1, u32::MAX).is_err());
        assert_eq!(base.with_appended_tool_results(0, 0, 512).unwrap(), base);
    }

    #[test]
    fn explicit_origin_wins_over_block_and_legacy_source() {
        let item = BlockItem::new(Block::A, "abc")
            .with_prompt_tax_source(PromptTaxSource::Skill)
            .with_prompt_origin(PromptOrigin::User);
        let result = PromptAttribution::from_retained_items(&[item], 3).unwrap();
        assert_eq!(result.counts(), [0, 0, 0, 0, 0, 3, 0]);
    }

    #[test]
    fn retained_unicode_unlabeled_and_residual() {
        let items = [
            BlockItem::new(Block::A, "é").with_prompt_origin(PromptOrigin::Retrieval),
            BlockItem::new(Block::A, "x"),
        ];
        let result = PromptAttribution::from_retained_items(&items, 8).unwrap();
        assert_eq!(result.counts(), [0, 0, 0, 2, 0, 0, 1]);
        assert_eq!(result.envelope_residual(), 5);
        assert_eq!(result.request_upper_bound(), 8);
        assert!(PromptAttribution::from_retained_items(&items, 2).is_err());
    }

    #[test]
    fn rejects_stale_estimates_overflow_and_unknown_estimator() {
        let mut item = BlockItem::new(Block::A, "é");
        item.tokens = 1;
        assert!(PromptAttribution::from_retained_items(&[item], 2).is_err());
        let overflow = serde_json::json!({
            "system": u32::MAX, "workflow": 1, "skill": 0, "retrieval": 0,
            "tool_result": 0, "user": 0, "unattributed": 0,
            "request_upper_bound": u32::MAX, "envelope_residual": 0,
            "estimator": "utf8_byte_upper_bound_v1"
        });
        assert!(serde_json::from_value::<PromptAttribution>(overflow).is_err());
        let zero = PromptAttribution::from_retained_items(&[], 0).unwrap();
        let mut unknown = serde_json::to_value(zero).unwrap();
        unknown["estimator"] = "future_estimator".into();
        assert!(serde_json::from_value::<PromptAttribution>(unknown).is_err());
    }

    #[test]
    fn serde_roundtrip_rejects_bad_total_and_unknown_fields() {
        let item = BlockItem::new(Block::A, "hello").with_prompt_origin(PromptOrigin::System);
        let original = PromptAttribution::from_retained_items(&[item], 9).unwrap();
        let encoded = serde_json::to_string(&original).unwrap();
        assert_eq!(
            serde_json::from_str::<PromptAttribution>(&encoded).unwrap(),
            original
        );
        let mut value = serde_json::to_value(original).unwrap();
        value["request_upper_bound"] = 10.into();
        assert!(serde_json::from_value::<PromptAttribution>(value).is_err());
        let mut value = serde_json::to_value(original).unwrap();
        value["unexpected"] = 1.into();
        assert!(serde_json::from_value::<PromptAttribution>(value).is_err());
    }

    #[test]
    fn seven_origins_survive_truncation_and_user_rewrites_lose_provenance() {
        use crate::tokens::budget::replace_user_message;
        let mut items: Vec<_> = [
            PromptOrigin::System,
            PromptOrigin::Workflow,
            PromptOrigin::Skill,
            PromptOrigin::Retrieval,
            PromptOrigin::ToolResult,
            PromptOrigin::User,
            PromptOrigin::Unattributed,
        ]
        .into_iter()
        .map(|origin| BlockItem::new(Block::D, "xy").with_prompt_origin(origin))
        .collect();
        items[5].block = Block::E;
        items[1].replace_content("x");
        let before = PromptAttribution::from_retained_items(&items, 15).unwrap();
        assert_eq!(before.counts(), [2, 1, 2, 2, 2, 2, 2]);
        assert_eq!(before.envelope_residual(), 2);
        replace_user_message(&mut items, "xy").unwrap();
        assert_eq!(items[5].prompt_origin, Some(PromptOrigin::User));
        replace_user_message(&mut items, "xy plus tool response").unwrap();
        assert_eq!(items[5].prompt_origin, None);
        let after = PromptAttribution::from_retained_items(&items, 40).unwrap();
        assert_eq!(after.counts()[5], 0);
        assert!(after.counts()[6] > before.counts()[6]);
    }

    #[test]
    fn rollup_overflow_preserves_previous_totals() {
        let mut totals = PromptComponentTotals {
            observed_call_count: u64::MAX,
            ..Default::default()
        };
        let before = totals;
        let value = PromptAttribution::from_retained_items(&[], 0).unwrap();
        assert!(totals.try_absorb(value).is_err());
        assert_eq!(totals, before);
    }
}
