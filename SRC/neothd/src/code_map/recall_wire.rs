//! Stable machine contract for repository-local recall consumers.
//!
//! CLI, MCP, GUI, Buddy and automation all serialize/parse this type. Keeping
//! the envelope here prevents each surface from inventing a subtly different
//! empty-result or generation shape.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::recall::RecallReceipt;

pub const RECALL_WIRE_SCHEMA: &str = "neoth.code_map.recall.v1";

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecallWireStatus {
    Ok,
    Unmapped,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecallWireHit {
    pub root: String,
    pub path: String,
    pub identifier_hits: u32,
    pub matched_symbols: Vec<String>,
    pub path_keyword_overlap: u32,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecallWireReceipt {
    pub root: String,
    pub root_identity: String,
    pub index_generation: i64,
    pub graph_generation: i64,
    /// `None` means the caller deliberately skipped the filesystem freshness
    /// scan. Consumers must not render that as "fresh".
    pub stale: Option<bool>,
    pub truncated: bool,
    pub hits: Vec<RecallWireHit>,
}

impl From<&RecallReceipt> for RecallWireReceipt {
    fn from(receipt: &RecallReceipt) -> Self {
        Self {
            root: receipt.snapshot.root.display().to_owned(),
            root_identity: receipt.snapshot.root.identity().as_str().to_owned(),
            index_generation: receipt.snapshot.index_generation,
            graph_generation: receipt.snapshot.graph_generation,
            stale: receipt.stale,
            truncated: receipt.truncated,
            hits: receipt
                .ranked_files
                .iter()
                .map(|hit| RecallWireHit {
                    root: hit.root.clone(),
                    path: hit.path.clone(),
                    identifier_hits: hit.identifier_hits,
                    matched_symbols: hit.matched_symbols.clone(),
                    path_keyword_overlap: hit.path_keyword_overlap,
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecallWireEnvelope {
    pub schema: String,
    pub status: RecallWireStatus,
    pub prompt: String,
    pub max: u64,
    pub receipt: Option<RecallWireReceipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl RecallWireEnvelope {
    pub fn success(prompt: impl Into<String>, max: usize, receipt: &RecallReceipt) -> Result<Self> {
        let envelope = Self {
            schema: RECALL_WIRE_SCHEMA.to_owned(),
            status: RecallWireStatus::Ok,
            prompt: prompt.into(),
            max: u64::try_from(max).map_err(anyhow::Error::from)?,
            receipt: Some(receipt.into()),
            note: None,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn empty(
        status: RecallWireStatus,
        prompt: impl Into<String>,
        max: usize,
        note: impl Into<String>,
    ) -> Result<Self> {
        if status == RecallWireStatus::Ok {
            bail!("empty recall envelope cannot use ok status");
        }
        let envelope = Self {
            schema: RECALL_WIRE_SCHEMA.to_owned(),
            status,
            prompt: prompt.into(),
            max: u64::try_from(max).map_err(anyhow::Error::from)?,
            receipt: None,
            note: Some(note.into()),
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn parse_json(input: &str) -> Result<Self> {
        let envelope: Self = serde_json::from_str(input)?;
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != RECALL_WIRE_SCHEMA {
            bail!(
                "unsupported recall schema {:?}; expected {RECALL_WIRE_SCHEMA}",
                self.schema
            );
        }
        if self.prompt.trim().is_empty() || self.max == 0 {
            bail!("recall envelope has an invalid prompt or max");
        }
        match (self.status, self.receipt.as_ref()) {
            (RecallWireStatus::Ok, Some(receipt)) => {
                if receipt.root.trim().is_empty() || receipt.root_identity.trim().is_empty() {
                    bail!("recall receipt has an invalid root identity");
                }
                if receipt.index_generation < 0 || receipt.graph_generation < 0 {
                    bail!("recall receipt has a negative generation");
                }
                for hit in &receipt.hits {
                    if hit.root != receipt.root || hit.path.trim().is_empty() {
                        bail!("recall hit is not bound to the receipt root");
                    }
                }
            }
            (RecallWireStatus::Ok, None) => bail!("ok recall envelope is missing its receipt"),
            (RecallWireStatus::Unmapped | RecallWireStatus::Unavailable, Some(_)) => {
                bail!("non-ok recall envelope must not carry a receipt")
            }
            (RecallWireStatus::Unmapped | RecallWireStatus::Unavailable, None) => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_empty_envelope_roundtrips() {
        let envelope = RecallWireEnvelope::empty(
            RecallWireStatus::Unavailable,
            "find auth",
            5,
            "index missing",
        )
        .unwrap();
        let json = serde_json::to_string(&envelope).unwrap();
        assert_eq!(RecallWireEnvelope::parse_json(&json).unwrap(), envelope);
    }

    #[test]
    fn parser_rejects_unknown_fields_and_status_receipt_mismatch() {
        let unknown = r#"{"schema":"neoth.code_map.recall.v1","status":"unavailable","prompt":"q","max":5,"receipt":null,"extra":true}"#;
        assert!(RecallWireEnvelope::parse_json(unknown).is_err());

        let mismatched = r#"{"schema":"neoth.code_map.recall.v1","status":"ok","prompt":"q","max":5,"receipt":null}"#;
        assert!(RecallWireEnvelope::parse_json(mismatched).is_err());
    }
}
