//! Validation for explicit physical numbering properties, without list resolution.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use super::ordered_range;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NumberingProperties {
    pub complete: bool,
    pub records: Vec<NumberingRecord>,
    omitted_observed: usize,
    omissions_limited: bool,
    omissions: Vec<NumberingOmission>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NumberingRecord {
    pub paragraph_source_range: [u64; 2],
    numbering_properties_source_range: [u64; 2],
    num_id: u32,
    level: Option<u8>,
    kind: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NumberingOmission {
    reason: String,
    source_range: [u64; 2],
}

pub(super) fn decode_numbering_properties<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<NumberingProperties>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    NumberingProperties::deserialize(deserializer).map(Some)
}

impl NumberingProperties {
    pub(super) fn validate(&self, entry_bytes: u64, scan_complete: bool) -> Result<()> {
        ensure!(
            self.records.len() <= 256
                && self.omissions.len() <= 64
                && self.omitted_observed <= 200_000,
            "numbering property limit exceeded"
        );
        ensure!(
            self.complete
                == (scan_complete
                    && self.omitted_observed == 0
                    && self.omissions.is_empty()
                    && !self.omissions_limited),
            "inconsistent numbering completeness"
        );
        let mut previous_end = 0;
        for record in &self.records {
            ordered_range(
                record.paragraph_source_range,
                [0, entry_bytes],
                &mut previous_end,
            )?;
            let [paragraph_start, paragraph_end] = record.paragraph_source_range;
            let [properties_start, properties_end] = record.numbering_properties_source_range;
            ensure!(
                paragraph_start < properties_start
                    && properties_start < properties_end
                    && properties_end < paragraph_end,
                "numbering properties must be strictly inside the paragraph"
            );
            ensure!(
                record.level.is_none_or(|level| level <= 8),
                "unsupported numbering level"
            );
            ensure!(
                record.kind
                    == if record.num_id == 0 {
                        "numbering_removed"
                    } else {
                        "numbering_reference"
                    },
                "invalid numbering kind"
            );
        }
        if self.omissions.iter().any(|item| item.reason == "metadata_limit") {
            ensure!(
                self.omissions.len() == 1
                    && self.omissions[0].source_range == [0, entry_bytes]
                    && self.records.is_empty()
                    && self.omissions_limited,
                "invalid numbering metadata summary"
            );
            return Ok(());
        }
        ensure!(
            if self.omissions_limited {
                self.omissions.len() == 64 && self.omitted_observed > 64
            } else {
                self.omissions.len() == self.omitted_observed
            },
            "inconsistent numbering omission detail count"
        );
        let mut previous_omission_end = 0;
        for omission in &self.omissions {
            ensure!(
                !omission.reason.is_empty()
                    && omission.reason.len() <= 64
                    && omission.reason.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
                "invalid numbering omission reason"
            );
            ordered_range(
                omission.source_range,
                [0, entry_bytes],
                &mut previous_omission_end,
            )?;
            ensure!(
                self.records.iter().all(|record|
                    omission.source_range[1] <= record.paragraph_source_range[0]
                    || omission.source_range[0] >= record.paragraph_source_range[1]),
                "numbering omission overlaps emitted paragraph"
            );
        }
        Ok(())
    }
}
