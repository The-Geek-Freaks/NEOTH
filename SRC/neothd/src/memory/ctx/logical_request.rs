//! Pure, strict request binding. Epochs and hashes never imply authorization.
use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, de::Error};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{DocumentProvenance, IndexRequest};

const EVENT_DOMAIN: &str = "neoth-ctx-logical-event-payload-v1";
const REVISION_DOMAIN: &str = "neoth-ctx-indexed-text-revision-v1";
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_CONTENT_BYTES: usize = 8 * 1024 * 1024;
const MAX_SCALAR_BYTES: usize = 8192;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LogicalContentRequest {
    pub label: String,
    pub content: String,
    #[serde(default)]
    pub file_path: Option<String>,
    #[serde(default = "super::default_content_type")]
    pub content_type: String,
    #[serde(default)]
    pub source_category: Option<String>,
    #[serde(default)]
    pub event_id: Option<String>,
    #[serde(default, deserialize_with = "strict_provenance")]
    pub document_provenance: Option<DocumentProvenance>,
}

fn strict_provenance<'de, D: Deserializer<'de>>(de: D) -> std::result::Result<Option<DocumentProvenance>, D::Error> {
    let Some(value) = Option::<Value>::deserialize(de)? else { return Ok(None) };
    let object = value.as_object().ok_or_else(|| D::Error::custom("provenance must be an object"))?;
    let allowed = [
        "schema", "parser_version", "source_bytes_sha256", "source_bytes",
        "extracted_text_sha256", "extracted_text_bytes", "extracted_text_encoding",
        "extracted_text_truncated", "structure",
    ];
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(D::Error::custom(format!("unknown document provenance field {key}")));
        }
    }
    serde_json::from_value(value).map(Some).map_err(D::Error::custom)
}

impl From<LogicalContentRequest> for IndexRequest {
    fn from(value: LogicalContentRequest) -> Self {
        Self {
            label: value.label, content: value.content, file_path: value.file_path,
            content_type: value.content_type, source_category: value.source_category,
            event_id: value.event_id, document_provenance: value.document_provenance,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CurrentGuard {
    pub source_id: i64,
    pub content_revision_id: String,
    pub current_event_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum LogicalMutationRequest {
    Register {
        logical_document_id: String,
        logical_event_id: String,
        authorization_epoch: u64,
        index: Box<LogicalContentRequest>,
    },
    Revise {
        logical_document_id: String,
        logical_event_id: String,
        authorization_epoch: u64,
        expected: CurrentGuard,
        index: Box<LogicalContentRequest>,
    },
    MetadataRename {
        logical_document_id: String,
        logical_event_id: String,
        authorization_epoch: u64,
        expected: CurrentGuard,
        new_label: String,
        #[serde(default)]
        new_file_path: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum LogicalAction { Register, Revise, MetadataRename }

#[derive(Debug)]
struct ValidatedIndex {
    request: IndexRequest,
    text_sha256: String,
    text_bytes: u64,
    raw_container_sha256: Option<String>,
    revision: String,
}

#[derive(Debug)]
enum Effect {
    Index(Box<ValidatedIndex>),
    Rename { label: String, path: Option<String> },
}

/// Only validate() constructs this type. There are no mutable accessors.
#[derive(Debug)]
pub(super) struct ValidatedLogicalMutation {
    action: LogicalAction,
    logical_id: String,
    event_id: String,
    epoch: i64,
    expected: Option<CurrentGuard>,
    digest: String,
    scalar_bytes: usize,
    effect: Effect,
}

pub(super) struct IndexedContentRef<'a>(&'a ValidatedIndex);
impl<'a> IndexedContentRef<'a> {
    pub(super) fn request(&self) -> &'a IndexRequest { &self.0.request }
    pub(super) fn indexed_text_sha256(&self) -> &'a str { &self.0.text_sha256 }
    pub(super) fn indexed_text_utf8_bytes(&self) -> u64 { self.0.text_bytes }
    pub(super) fn raw_container_sha256(&self) -> Option<&'a str> { self.0.raw_container_sha256.as_deref() }
}

impl ValidatedLogicalMutation {
    pub(super) fn action(&self) -> LogicalAction { self.action }
    pub(super) fn logical_document_id(&self) -> &str { &self.logical_id }
    pub(super) fn logical_event_id(&self) -> &str { &self.event_id }
    pub(super) fn authorization_epoch(&self) -> i64 { self.epoch }
    pub(super) fn expected(&self) -> Option<&CurrentGuard> { self.expected.as_ref() }
    pub(super) fn request_semantics_sha256(&self) -> &str { &self.digest }
    pub(super) fn content_revision_id(&self) -> Option<&str> {
        match &self.effect { Effect::Index(value) => Some(&value.revision), Effect::Rename { .. } => None }
    }
    pub(super) fn indexed_content(&self) -> Option<IndexedContentRef<'_>> {
        match &self.effect { Effect::Index(value) => Some(IndexedContentRef(value)), Effect::Rename { .. } => None }
    }
    pub(super) fn rename_metadata(&self) -> Option<(&str, Option<&str>)> {
        match &self.effect {
            Effect::Rename { label, path } => Some((label, path.as_deref())),
            Effect::Index(_) => None,
        }
    }
}

pub(super) fn validate(request: LogicalMutationRequest) -> Result<ValidatedLogicalMutation> {
    let (action, logical_id, event_id, epoch, expected, index, rename) = match request {
        LogicalMutationRequest::Register { logical_document_id, logical_event_id, authorization_epoch, index } =>
            (LogicalAction::Register, logical_document_id, logical_event_id, authorization_epoch, None, Some(index), None),
        LogicalMutationRequest::Revise { logical_document_id, logical_event_id, authorization_epoch, expected, index } =>
            (LogicalAction::Revise, logical_document_id, logical_event_id, authorization_epoch, Some(expected), Some(index), None),
        LogicalMutationRequest::MetadataRename { logical_document_id, logical_event_id, authorization_epoch, expected, new_label, new_file_path } =>
            (LogicalAction::MetadataRename, logical_document_id, logical_event_id, authorization_epoch, Some(expected), None, Some((new_label, new_file_path))),
    };
    // Cheap identity checks precede content hashing and provenance validation.
    validate_identifier("logical_document_id", &logical_id)?;
    validate_identifier("logical_event_id", &event_id)?;
    let epoch = i64::try_from(epoch).context("logical epoch exceeds SQLite range")?;
    let mut scalar_bytes = checked_sum(&[logical_id.len(), event_id.len()])?;
    if let Some(guard) = &expected {
        ensure!(guard.source_id > 0, "expected source id must be positive");
        ensure!(guard.content_revision_id.len() == 64 && guard.content_revision_id.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "invalid expected revision");
        validate_identifier("expected current_event_id", &guard.current_event_id)?;
        scalar_bytes = checked_sum(&[scalar_bytes, guard.content_revision_id.len(), guard.current_event_id.len()])?;
    }
    let (effect, canonical_effect) = if let Some(index) = index {
        let request: IndexRequest = (*index).into();
        ensure!(request.content.len() <= MAX_CONTENT_BYTES, "logical content exceeds 8 MiB");
        scalar_bytes = checked_sum(&[scalar_bytes, request.label.len(), request.content_type.len(),
            request.file_path.as_deref().map_or(0, str::len),
            request.source_category.as_deref().map_or(0, str::len),
            request.event_id.as_deref().map_or(0, str::len)])?;
        ensure!(scalar_bytes <= MAX_SCALAR_BYTES, "logical scalar metadata exceeds 8192 bytes");
        if let Some(provenance) = &request.document_provenance {
            provenance.validate_for_content(&request.content)?;
        }
        let text_sha256 = format!("{:x}", Sha256::digest(request.content.as_bytes()));
        let text_bytes = u64::try_from(request.content.len())?;
        let raw_container_sha256 = request.document_provenance.as_ref()
            .map(|value| value.source_bytes_sha256.clone());
        let payload = json!({
            "label": request.label, "file_path": request.file_path,
            "content_type": request.content_type, "source_category": request.source_category,
            "source_event_id": request.event_id, "document_provenance": request.document_provenance,
            "indexed_text_sha256": text_sha256, "indexed_text_utf8_bytes": text_bytes,
            "raw_container_sha256": raw_container_sha256,
        });
        let revision = domain_hash(REVISION_DOMAIN, &[logical_id.as_bytes(), text_sha256.as_bytes()]);
        (Effect::Index(Box::new(ValidatedIndex { request, text_sha256, text_bytes, raw_container_sha256, revision })), payload)
    } else {
        let (label, path) = rename.context("missing logical mutation payload")?;
        scalar_bytes = checked_sum(&[scalar_bytes, label.len(), path.as_deref().map_or(0, str::len)])?;
        ensure!(scalar_bytes <= MAX_SCALAR_BYTES, "logical scalar metadata exceeds 8192 bytes");
        let payload = json!({"new_label": label, "new_file_path": path});
        (Effect::Rename { label, path }, payload)
    };
    let canonical = sort_json(json!({
        "version": 1, "action": action, "logical_document_id": logical_id,
        "logical_event_id": event_id, "authorization_epoch": epoch,
        "expected": expected, "payload": canonical_effect,
    }));
    let digest = domain_hash(EVENT_DOMAIN, &[&serde_json::to_vec(&canonical)?]);
    Ok(ValidatedLogicalMutation { action, logical_id, event_id, epoch, expected, digest, scalar_bytes, effect })
}

pub(super) fn lineage_metadata_bytes(old_label: &str, old_path: Option<&str>, request: &ValidatedLogicalMutation) -> Result<usize> {
    ensure!(request.rename_metadata().is_some(), "lineage aggregate requires rename");
    let size = checked_sum(&[old_label.len(), old_path.map_or(0, str::len), request.scalar_bytes])?;
    ensure!(size <= MAX_SCALAR_BYTES, "rename lineage metadata exceeds 8192 bytes");
    Ok(size)
}

pub(super) fn validate_identifier(name: &str, value: &str) -> Result<()> {
    ensure!(!value.is_empty() && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')),
        "invalid {name}");
    Ok(())
}

fn checked_sum(values: &[usize]) -> Result<usize> {
    values.iter().try_fold(0usize, |sum, value| sum.checked_add(*value).context("metadata byte count overflow"))
}

fn domain_hash(domain: &str, values: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    for value in std::iter::once(domain.as_bytes()).chain(values.iter().copied()) {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    format!("{:x}", hash.finalize())
}

fn sort_json(value: Value) -> Value {
    match value {
        Value::Object(values) => Value::Object(values.into_iter()
            .map(|(key, value)| (key, sort_json(value))).collect::<BTreeMap<_, _>>().into_iter().collect()),
        Value::Array(values) => Value::Array(values.into_iter().map(sort_json).collect()),
        scalar => scalar,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn wire() -> Value {
        json!({"action":"register","logical_document_id":"doc-1","logical_event_id":"event-1",
            "authorization_epoch":0,"index":{"label":"manual","content":"source text","content_type":"prose"}})
    }
    fn validated(value: Value) -> ValidatedLogicalMutation {
        validate(serde_json::from_value(value).unwrap()).unwrap()
    }
    fn provenance() -> Value {
        json!({"schema":"neoth.document-provenance.v1","parser_version":"document-extractor/v1",
            "source_bytes_sha256":"a".repeat(64),"source_bytes":100,
            "extracted_text_sha256":format!("{:x}",Sha256::digest(b"source text")),
            "extracted_text_bytes":11,"extracted_text_encoding":"utf-8","extracted_text_truncated":false})
    }
    #[test]
    fn logical_digest_binds_each_semantic_field_and_independent_event() {
        let base = validated(wire());
        for (key, value) in [
            ("label",json!("other")),("content",json!("different text")),
            ("file_path",json!("manual.md")),("content_type",json!("code")),
            ("source_category",json!("manuals")),("event_id",json!("source-event")),
            ("document_provenance",provenance()),
        ] {
            let mut changed=wire(); changed["index"][key]=value;
            assert_ne!(base.request_semantics_sha256(),validated(changed).request_semantics_sha256(),"{key}");
        }
        let mut changed=wire(); changed["logical_event_id"]=json!("event-2");
        assert_ne!(base.request_semantics_sha256(),validated(changed).request_semantics_sha256());
    }
    #[test]
    fn logical_options_normalize_null_but_preserve_present_empty() {
        let mut null=wire(); null["index"]["file_path"]=Value::Null;
        let mut empty=wire(); empty["index"]["file_path"]=json!("");
        assert_eq!(validated(wire()).request_semantics_sha256(),validated(null).request_semantics_sha256());
        assert_ne!(validated(wire()).request_semantics_sha256(),validated(empty).request_semantics_sha256());
    }
    #[test]
    fn logical_wire_rejects_unknown_outer_index_and_provenance_fields() {
        let mut outer=wire(); outer["raw_container_sha256"]=json!("a".repeat(64));
        let mut index=wire(); index["index"]["raw_container_sha256"]=json!("a".repeat(64));
        let mut nested=wire(); nested["index"]["document_provenance"]=provenance();
        nested["index"]["document_provenance"]["invented"]=json!(true);
        for input in [outer,index,nested] {
            assert!(serde_json::from_value::<LogicalMutationRequest>(input).is_err());
        }
    }
    #[test]
    fn logical_identity_validation_precedes_provenance_hash_checks() {
        let mut input=wire(); input["logical_document_id"]=json!("bad id");
        input["index"]["document_provenance"]=provenance();
        input["index"]["document_provenance"]["extracted_text_sha256"]=json!("b".repeat(64));
        let error=validate(serde_json::from_value(input).unwrap()).unwrap_err().to_string();
        assert!(error.contains("logical_document_id"),"{error}");
    }
    #[test]
    fn logical_raw_container_remains_unknown_without_provenance() {
        let request=validated(wire());
        assert!(request.indexed_content().unwrap().raw_container_sha256().is_none());
        let mut input=wire(); input["index"]["document_provenance"]=provenance();
        let with=validated(input.clone());
        assert_eq!(with.indexed_content().unwrap().raw_container_sha256(),Some("a".repeat(64).as_str()));
        input["index"]["document_provenance"]["source_bytes"]=json!(101);
        assert_ne!(with.request_semantics_sha256(),validated(input).request_semantics_sha256());
    }
    #[test]
    fn logical_content_limit_and_epoch_overflow_fail_before_effects() {
        let mut input=wire(); input["authorization_epoch"]=json!(u64::MAX);
        assert!(validate(serde_json::from_value(input).unwrap()).is_err());
        let mut input=wire(); input["index"]["content"]=json!("x".repeat(MAX_CONTENT_BYTES+1));
        assert!(validate(serde_json::from_value(input).unwrap()).is_err());
    }
    #[test]
    fn logical_rename_has_no_content_and_counts_lineage_once() {
        let input=json!({"action":"metadata_rename","logical_document_id":"doc-1","logical_event_id":"rename-1",
            "authorization_epoch":0,"expected":{"source_id":1,"content_revision_id":"a".repeat(64),
            "current_event_id":"event-1"},"new_label":"renamed","new_file_path":null});
        let request=validated(input.clone());
        assert!(request.indexed_content().is_none());
        assert!(request.content_revision_id().is_none());
        let old="x".repeat(MAX_SCALAR_BYTES-request.scalar_bytes);
        assert_eq!(lineage_metadata_bytes(&old,None,&request).unwrap(),MAX_SCALAR_BYTES);
        assert!(lineage_metadata_bytes(&(old+"x"),None,&request).is_err());
        let mut content=input; content["index"]=wire()["index"].clone();
        assert!(serde_json::from_value::<LogicalMutationRequest>(content).is_err());
    }
    #[test]
    fn logical_canonicalization_sorts_nested_objects_and_separates_fields() {
        assert_eq!(sort_json(json!({"b":{"d":2,"c":1},"a":0})),
            sort_json(json!({"a":0,"b":{"c":1,"d":2}})));
        assert_ne!(domain_hash("scope",&[b"ab",b"c"]),domain_hash("scope",&[b"a",b"bc"]));
        assert_ne!(domain_hash("scope",&[b"a"]),domain_hash("other",&[b"a"]));
    }
}
