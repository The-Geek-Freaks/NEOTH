//! Hash-bound provenance for code-map context supplied to the coding decomposer.
//!
//! A receipt deliberately records selection metadata and commitments only.  The
//! assembled context and provider prompt remain transient; persisting either
//! would turn the kanban index into an unbounded source-code/prompt archive.

use std::io::{self, Write};
use std::path::{Component, Path};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::types::KanbanSessionId;

/// Stable wire schema for [`CodingCodeMapReceipt`].
pub const CODING_CODE_MAP_RECEIPT_SCHEMA: &str = "neoth.coding.code_map_receipt.v1";

/// Receipt payloads are kept small enough to remain a session attribute, not a
/// second context store.
pub const MAX_CODE_MAP_RECEIPT_BYTES: usize = 128 * 1024;
/// Maximum serialized metadata for one context source after sanitization.
/// Two sources therefore consume at most 112 KiB of the 128 KiB session field;
/// the repair receipt stores only its changing commitments rather than a second
/// source copy.
pub(crate) const MAX_CODE_MAP_SOURCE_BYTES: usize = 56 * 1024;
const MAX_CONTEXT_BYTES: usize = 64 * 1024;
const MAX_SOURCES: usize = 2;
const MAX_ROOT_BYTES: usize = 4 * 1024;
const MAX_ROOT_IDENTITY_BYTES: usize = 4 * 1024;
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_SYMBOL_BYTES: usize = 512;

/// Why a code-map selection was included in the original assembled context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeMapContextKind {
    TargetedRecall,
    RepoMapSummary,
}

/// Symbols selected from one repository-relative file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeMapSelectedFile {
    pub path: String,
    pub symbols: Vec<String>,
}

/// A depth-one caller retained with the original context selection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeMapCaller {
    pub target_symbol: String,
    pub caller_symbol: String,
    pub caller_path: String,
}

/// Typed, freshness-bound provenance for one portion of the original context.
///
/// This type intentionally contains names and paths only. It has no field for
/// source code, context text, an operator prompt, or provider output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeMapContextSource {
    pub kind: CodeMapContextKind,
    pub root: String,
    pub root_identity: String,
    pub index_generation: i64,
    pub graph_generation: i64,
    pub stale: bool,
    pub selection_truncated: bool,
    /// True when source metadata was redacted at the prepared-context boundary.
    /// Old clean receipts deserialize as false; a raw secret-shaped value is
    /// never accepted merely because this field is absent.
    #[serde(default)]
    pub metadata_redacted: bool,
    pub selected_files: Vec<CodeMapSelectedFile>,
    pub callers: Vec<CodeMapCaller>,
}

impl CodeMapContextSource {
    /// Validate one source independently of the other sources in an assembled
    /// context. [`PreparedCodeMapContext::new`] also checks that all sources
    /// describe the same snapshot.
    pub fn validate(&self) -> Result<()> {
        self.validate_shape()?;
        ensure!(
            sanitize_metadata_value(&self.root_identity) == self.root_identity,
            "code-map root identity contains unsanitized metadata"
        );
        ensure!(
            source_metadata_is_sanitized(self),
            "code-map source contains unsanitized metadata"
        );
        ensure!(
            self.metadata_redacted || !source_contains_redaction_marker(self),
            "redacted code-map metadata must set metadata_redacted"
        );
        ensure_source_payload_bounded(self)?;
        Ok(())
    }

    /// Sanitize the metadata that may be persisted in a receipt. Root identity
    /// is a physical-root binding and cannot be transformed without changing
    /// its meaning, so it fails closed if canonical sanitization would alter it.
    pub(crate) fn sanitize_metadata_for_receipt(&mut self) -> Result<()> {
        self.validate_shape()?;
        ensure!(
            sanitize_metadata_value(&self.root_identity) == self.root_identity,
            "code-map root identity cannot be redacted without losing its physical binding"
        );

        // Retain a prior true value: sanitization is a boundary operation and
        // must be idempotent when a bounded producer pre-sanitizes metadata
        // before it hands the source to `PreparedCodeMapContext::new`.
        let mut metadata_redacted = self.metadata_redacted;
        sanitize_metadata_field(&mut self.root, &mut metadata_redacted);
        for file in &mut self.selected_files {
            sanitize_metadata_field(&mut file.path, &mut metadata_redacted);
            for symbol in &mut file.symbols {
                sanitize_metadata_field(symbol, &mut metadata_redacted);
            }
        }
        for caller in &mut self.callers {
            sanitize_metadata_field(&mut caller.target_symbol, &mut metadata_redacted);
            sanitize_metadata_field(&mut caller.caller_symbol, &mut metadata_redacted);
            sanitize_metadata_field(&mut caller.caller_path, &mut metadata_redacted);
        }
        self.metadata_redacted = metadata_redacted;
        self.validate_shape()?;
        Ok(())
    }

    fn validate_shape(&self) -> Result<()> {
        bounded_nonempty("code-map root", &self.root, MAX_ROOT_BYTES)?;
        bounded_nonempty(
            "code-map root identity",
            &self.root_identity,
            MAX_ROOT_IDENTITY_BYTES,
        )?;
        ensure!(
            self.index_generation > 0
                && self.graph_generation > 0
                && self.index_generation == self.graph_generation,
            "code-map source must have matching positive index and graph generations"
        );
        ensure!(
            !self.stale,
            "stale code-map sources must not be used for coding context"
        );
        for file in &self.selected_files {
            relative_contained_path("code-map selected-file path", &file.path)?;
            for symbol in &file.symbols {
                bounded_nonempty("code-map selected symbol", symbol, MAX_SYMBOL_BYTES)?;
            }
        }
        for caller in &self.callers {
            bounded_nonempty(
                "code-map target symbol",
                &caller.target_symbol,
                MAX_SYMBOL_BYTES,
            )?;
            bounded_nonempty(
                "code-map caller symbol",
                &caller.caller_symbol,
                MAX_SYMBOL_BYTES,
            )?;
            relative_contained_path("code-map caller path", &caller.caller_path)?;
        }
        Ok(())
    }
}

/// The assembled code-map text before the decomposer applies its independent
/// input budget. The text is intentionally private and never serializable.
#[derive(Clone, Debug)]
pub struct PreparedCodeMapContext {
    text: String,
    sources: Vec<CodeMapContextSource>,
}

impl PreparedCodeMapContext {
    /// Bind the exact pre-budget context to validated source provenance.
    pub fn new(text: String, mut sources: Vec<CodeMapContextSource>) -> Result<Self> {
        ensure!(
            !text.is_empty(),
            "prepared code-map context must contain the original assembled text"
        );
        ensure!(
            text.len() <= MAX_CONTEXT_BYTES,
            "prepared code-map context exceeds {} bytes",
            MAX_CONTEXT_BYTES
        );
        for source in &mut sources {
            source.sanitize_metadata_for_receipt()?;
        }
        validate_sources(&sources)?;
        Ok(Self { text, sources })
    }

    /// Original assembled code-map text, before decomposer truncation.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Immutable provenance for the original selection.
    pub fn sources(&self) -> &[CodeMapContextSource] {
        &self.sources
    }

    /// Commit the exact strings used in a decomposition attempt without
    /// retaining those strings in the serializable receipt.
    pub fn receipt(
        &self,
        session_id: KanbanSessionId,
        attempt: u8,
        operator_prompt: &str,
        submitted_context: &str,
        provider_prompt: &str,
    ) -> Result<CodingCodeMapReceipt> {
        ensure!(
            submitted_context.len() <= MAX_CONTEXT_BYTES,
            "submitted code-map context exceeds {} bytes",
            MAX_CONTEXT_BYTES
        );
        let receipt = CodingCodeMapReceipt {
            schema: CODING_CODE_MAP_RECEIPT_SCHEMA.to_owned(),
            session_id: session_id.raw(),
            attempt,
            operator_prompt_sha256: sha256_hex(operator_prompt),
            assembled_context_sha256: sha256_hex(&self.text),
            submitted_context_sha256: sha256_hex(submitted_context),
            submitted_context_bytes: submitted_context.len(),
            context_truncated: submitted_context != self.text,
            provider_prompt_sha256: sha256_hex(provider_prompt),
            sources: self.sources.clone(),
        };
        receipt.validate()?;
        Ok(receipt)
    }
}

/// Persistable commitment to one provider decomposition attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodingCodeMapReceipt {
    pub schema: String,
    pub session_id: i64,
    pub attempt: u8,
    pub operator_prompt_sha256: String,
    pub assembled_context_sha256: String,
    pub submitted_context_sha256: String,
    pub submitted_context_bytes: usize,
    pub context_truncated: bool,
    pub provider_prompt_sha256: String,
    pub sources: Vec<CodeMapContextSource>,
}

impl CodingCodeMapReceipt {
    /// Validate a receipt loaded from persistence or supplied by a caller.
    /// No fallback is allowed: malformed receipts are evidence of corruption.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == CODING_CODE_MAP_RECEIPT_SCHEMA,
            "unsupported coding code-map receipt schema"
        );
        ensure!(self.session_id > 0, "receipt session id must be positive");
        ensure!(
            matches!(self.attempt, 1 | 2),
            "receipt attempt must be either 1 or 2"
        );
        for (name, digest) in [
            ("operator prompt", &self.operator_prompt_sha256),
            ("assembled context", &self.assembled_context_sha256),
            ("submitted context", &self.submitted_context_sha256),
            ("provider prompt", &self.provider_prompt_sha256),
        ] {
            ensure!(
                is_lowercase_sha256(digest),
                "{name} digest is not lowercase SHA-256"
            );
        }
        ensure!(
            self.submitted_context_bytes <= MAX_CONTEXT_BYTES,
            "submitted code-map context byte length exceeds bound"
        );
        ensure!(
            self.context_truncated
                == (self.assembled_context_sha256 != self.submitted_context_sha256),
            "context_truncated must exactly match the assembled/submitted commitments"
        );
        validate_sources(&self.sources)
    }
}

fn validate_sources(sources: &[CodeMapContextSource]) -> Result<()> {
    ensure!(
        !sources.is_empty() && sources.len() <= MAX_SOURCES,
        "prepared code-map context must have one or two provenance sources"
    );
    let first = &sources[0];
    first.validate()?;
    for source in &sources[1..] {
        source.validate()?;
        ensure!(
            source.root == first.root
                && source.root_identity == first.root_identity
                && source.index_generation == first.index_generation
                && source.graph_generation == first.graph_generation,
            "all code-map context sources must describe the same snapshot"
        );
        ensure!(
            source.kind != first.kind,
            "duplicate code-map context source kind"
        );
    }
    Ok(())
}

fn bounded_nonempty(name: &str, value: &str, max_bytes: usize) -> Result<()> {
    ensure!(!value.is_empty(), "{name} must not be empty");
    ensure!(value.len() <= max_bytes, "{name} exceeds {max_bytes} bytes");
    ensure!(
        !value.contains('\0') && !value.contains('\r') && !value.contains('\n'),
        "{name} contains an unsafe control character"
    );
    Ok(())
}

fn relative_contained_path(name: &str, value: &str) -> Result<()> {
    bounded_nonempty(name, value, MAX_PATH_BYTES)?;
    // `Path` follows the host platform. Reject Windows separators and drive
    // prefixes explicitly too so a receipt has the same containment semantics
    // when inspected on a different host.
    ensure!(
        !value.contains('\\') && path_colons_are_redaction_markers(value),
        "{name} must use a relative slash-separated repository path"
    );
    let path = Path::new(value);
    ensure!(!path.is_absolute(), "{name} must be relative");
    for component in path.components() {
        ensure!(
            matches!(component, Component::Normal(_)),
            "{name} must remain contained within its repository root"
        );
    }
    Ok(())
}

fn sanitize_metadata_value(value: &str) -> String {
    crate::security::redact::sanitize_tool_output(value)
}

fn ensure_source_payload_bounded(source: &CodeMapContextSource) -> Result<()> {
    // Keep the size proof exact without allocating a second, potentially
    // attacker-influenced JSON buffer. The source itself is trusted in-process
    // data and producers budget it too, but a bounded writer ensures this
    // validation step cannot add an unbounded allocation of its own.
    let mut writer = BoundedJsonWriter::new(MAX_CODE_MAP_SOURCE_BYTES);
    match serde_json::to_writer(&mut writer, source) {
        Ok(()) => {}
        Err(_error) if writer.exceeded => {
            anyhow::bail!(
                "serialized code-map source exceeds {} bytes",
                MAX_CODE_MAP_SOURCE_BYTES
            );
        }
        Err(error) => return Err(error).context("serialize code-map source for size check"),
    }
    Ok(())
}

struct BoundedJsonWriter {
    limit: usize,
    written: usize,
    exceeded: bool,
}

impl BoundedJsonWriter {
    const fn new(limit: usize) -> Self {
        Self {
            limit,
            written: 0,
            exceeded: false,
        }
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.written) {
            self.exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "code-map source byte budget exceeded",
            ));
        }
        self.written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn sanitize_metadata_field(value: &mut String, metadata_redacted: &mut bool) {
    let sanitized = sanitize_metadata_value(value);
    if sanitized != *value {
        *metadata_redacted = true;
        *value = sanitized;
    }
}

fn source_contains_redaction_marker(source: &CodeMapContextSource) -> bool {
    source.root.contains("[REDACTED:")
        || source.selected_files.iter().any(|file| {
            file.path.contains("[REDACTED:")
                || file
                    .symbols
                    .iter()
                    .any(|symbol| symbol.contains("[REDACTED:"))
        })
        || source.callers.iter().any(|caller| {
            caller.target_symbol.contains("[REDACTED:")
                || caller.caller_symbol.contains("[REDACTED:")
                || caller.caller_path.contains("[REDACTED:")
        })
}

fn source_metadata_is_sanitized(source: &CodeMapContextSource) -> bool {
    sanitize_metadata_value(&source.root) == source.root
        && source.selected_files.iter().all(|file| {
            sanitize_metadata_value(&file.path) == file.path
                && file
                    .symbols
                    .iter()
                    .all(|symbol| sanitize_metadata_value(symbol) == symbol.as_str())
        })
        && source.callers.iter().all(|caller| {
            sanitize_metadata_value(&caller.target_symbol) == caller.target_symbol.as_str()
                && sanitize_metadata_value(&caller.caller_symbol) == caller.caller_symbol.as_str()
                && sanitize_metadata_value(&caller.caller_path) == caller.caller_path.as_str()
        })
}

/// Sanitization markers contain a colon (`[REDACTED:kind]`), which is not a
/// Windows drive prefix. Every other colon remains forbidden so receipt paths
/// stay portable and contained even when inspected off their source host.
fn path_colons_are_redaction_markers(value: &str) -> bool {
    let mut remaining = value;
    while let Some(colon) = remaining.find(':') {
        let before = &remaining[..colon];
        if !before.ends_with("[REDACTED") {
            return false;
        }
        let after = &remaining[colon + 1..];
        let Some(end) = after.find(']') else {
            return false;
        };
        let kind = &after[..end];
        if kind.is_empty()
            || !kind
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_' || byte.is_ascii_digit())
        {
            return false;
        }
        remaining = &after[end + 1..];
    }
    true
}

fn sha256_hex(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(kind: CodeMapContextKind) -> CodeMapContextSource {
        CodeMapContextSource {
            kind,
            root: "C:/repo".to_owned(),
            root_identity: "volume-serial:repo-id".to_owned(),
            index_generation: 7,
            graph_generation: 7,
            stale: false,
            selection_truncated: false,
            metadata_redacted: false,
            selected_files: vec![CodeMapSelectedFile {
                path: "src/lib.rs".to_owned(),
                symbols: vec!["entrypoint".to_owned()],
            }],
            callers: vec![CodeMapCaller {
                target_symbol: "entrypoint".to_owned(),
                caller_symbol: "main".to_owned(),
                caller_path: "src/main.rs".to_owned(),
            }],
        }
    }

    #[test]
    fn source_validation_rejects_stale_cross_root_and_escaping_paths() {
        let mut stale = source(CodeMapContextKind::TargetedRecall);
        stale.stale = true;
        assert!(stale.validate().is_err());

        let first = source(CodeMapContextKind::TargetedRecall);
        let mut other_root = source(CodeMapContextKind::RepoMapSummary);
        other_root.root = "C:/other".to_owned();
        assert!(
            PreparedCodeMapContext::new("context".to_owned(), vec![first, other_root]).is_err()
        );

        let mut escaping = source(CodeMapContextKind::TargetedRecall);
        escaping.selected_files[0].path = "../secret.rs".to_owned();
        assert!(escaping.validate().is_err());
    }

    #[test]
    fn prepared_context_redacts_metadata_and_refuses_raw_or_mutable_identity() {
        let root_secret = "sk-proj-0123456789abcdefghijklmnop";
        let path_secret = "ghp_123456789012345678901234567890";
        let aws_secret = "AKIA1234567890ABCDEF";
        let mut raw = source(CodeMapContextKind::TargetedRecall);
        raw.root = format!("C:/repo/{root_secret}");
        raw.selected_files[0].path = format!("src/{path_secret}.rs");
        raw.selected_files[0].symbols = vec![aws_secret.to_owned()];
        raw.callers[0].target_symbol = root_secret.to_owned();
        raw.callers[0].caller_symbol = path_secret.to_owned();
        raw.callers[0].caller_path = format!("src/{aws_secret}.rs");
        assert!(
            raw.validate().is_err(),
            "public raw metadata cannot bypass validation"
        );

        let prepared = PreparedCodeMapContext::new("context".to_owned(), vec![raw]).unwrap();
        let sanitized_source = &prepared.sources()[0];
        assert!(sanitized_source.metadata_redacted);
        let prepared_again =
            PreparedCodeMapContext::new("context".to_owned(), prepared.sources().to_vec()).unwrap();
        assert!(
            prepared_again.sources()[0].metadata_redacted,
            "metadata redaction provenance must survive repeated preparation"
        );
        let mut marker_without_flag = sanitized_source.clone();
        marker_without_flag.metadata_redacted = false;
        assert!(marker_without_flag.validate().is_err());
        let receipt = prepared
            .receipt(KanbanSessionId(1), 1, "operator", "context", "provider")
            .unwrap();
        let serialized = serde_json::to_string(&receipt).unwrap();
        for secret in [root_secret, path_secret, aws_secret] {
            assert!(!serialized.contains(secret), "raw metadata secret leaked");
        }
        assert!(serialized.contains("[REDACTED:"));

        let mut mutable_identity = source(CodeMapContextKind::TargetedRecall);
        mutable_identity.root_identity = root_secret.to_owned();
        assert!(
            PreparedCodeMapContext::new("context".to_owned(), vec![mutable_identity]).is_err(),
            "root identity must remain the exact physical-root identifier"
        );
    }

    #[test]
    fn receipt_hashes_exact_utf8_bytes_and_records_truncation_without_leaking_input() {
        let prepared = PreparedCodeMapContext::new(
            "é context".to_owned(),
            vec![source(CodeMapContextKind::TargetedRecall)],
        )
        .unwrap();
        let receipt = prepared
            .receipt(KanbanSessionId(42), 1, "operator 🔒", "é", "provider 🔒")
            .unwrap();
        assert_eq!(receipt.submitted_context_bytes, "é".len());
        assert!(receipt.context_truncated);
        assert_eq!(receipt.operator_prompt_sha256, sha256_hex("operator 🔒"));
        assert_eq!(receipt.submitted_context_sha256, sha256_hex("é"));

        let serialized = serde_json::to_string(&receipt).unwrap();
        assert!(!serialized.contains("operator 🔒"));
        assert!(!serialized.contains("provider 🔒"));
        assert!(!serialized.contains("é context"));
    }

    #[test]
    fn receipt_rejects_unknown_fields_and_noncanonical_digest() {
        let prepared = PreparedCodeMapContext::new(
            "context".to_owned(),
            vec![source(CodeMapContextKind::TargetedRecall)],
        )
        .unwrap();
        let mut receipt = prepared
            .receipt(KanbanSessionId(1), 1, "operator", "context", "provider")
            .unwrap();
        receipt.operator_prompt_sha256.make_ascii_uppercase();
        assert!(receipt.validate().is_err());

        let json = serde_json::to_string(
            &prepared
                .receipt(KanbanSessionId(1), 1, "o", "context", "p")
                .unwrap(),
        )
        .unwrap();
        let injected = json.replacen('}', ",\"raw_context\":\"leak\"}", 1);
        assert!(serde_json::from_str::<CodingCodeMapReceipt>(&injected).is_err());
    }
}
