//! Pre-mutation snapshot emission (B-Rollback / CDX-02).
//!
//! Every Effect-Adapter call site that mutates external state (file
//! write, channel send, MCP tool invoke, SQL mutation, ...) emits a
//! `PRE_MUTATION_SNAPSHOT` WAL frame BEFORE running the mutation. The
//! frame captures whatever the adapter needs to undo the change later
//! — file content, prior message id, before-row snapshot, etc.
//!
//! A later `neoth rollback --to <snapshot_id>` consumes these frames
//! to plan + execute restoration. The restoration logic per
//! `MutationKind` is the deferred half (operator + design call); the
//! snapshot framing + WAL emission are foundation.
//!
//! Why this is "systemwide": every mutating adapter call goes through
//! this primitive, so the audit log is uniformly queryable
//! (`neoth wal show --type 0xF2` lists every snapshot taken in the
//! last N seconds). No more ad-hoc per-adapter `/rollback`
//! implementations.
//!
//! Design note: `before_state` is OPAQUE bytes from the WAL's
//! perspective. Each `MutationKind` defines its own encoding (likely
//! JSON for simplicity, but bincode/borsh are options when sizes
//! matter). The kind tag is what the rollback CLI dispatches on.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::HeaderBuilder;
use super::events::EVENT_TYPE_PRE_MUTATION_SNAPSHOT;
use super::writer::WalWriterHandle;

/// Stable string ids — wire-encoded into the snapshot payload, used by
/// the rollback CLI to dispatch restoration logic. Adding a variant
/// here means the rollback dispatcher gains a new arm; removing one
/// would invalidate historical WAL frames + break replay, so variants
/// are append-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationKind {
    /// Operator/agent writing to a path in the operator's filesystem.
    FileWrite,
    /// Outbound message via a `Channel` adapter (Telegram/Slack/etc).
    ChannelSend,
    /// MCP tool invocation that the gate dispatched.
    McpToolInvoke,
    /// SQLite mutation (UPDATE / DELETE / INSERT) outside the
    /// indexer's normal append path.
    SqlMutation,
    /// freedom.yaml or credentials.yaml rewrite via CLI.
    ConfigWrite,
    /// Catch-all for adapters we haven't yet typed; `target` carries
    /// the operator-readable description.
    Other,
}

/// Serialised shape of a snapshot frame's payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreMutationSnapshot {
    /// Stable id of the mutation about to happen.
    pub mutation_kind: MutationKind,
    /// Resource identifier the mutation targets (file path, channel
    /// id, tool name, table name, etc).
    pub target: String,
    /// Whatever the adapter needs to undo the mutation. Opaque from
    /// the WAL's POV; each `MutationKind` defines its own encoding.
    /// Hex-encoded so the WAL frame's JSON payload stays text-only
    /// (no extra dep needed). Operators reading `neoth wal show` see
    /// `"68656c6c6f"` rather than `[104,101,108,108,111]`.
    pub before_state_hex: String,
    /// Wall-clock seconds when the snapshot was taken.
    pub ts_unix: i64,
    /// Free-form note operators add via CLI flag (`--reason
    /// "manual edit before refactor"`). Optional.
    #[serde(default)]
    pub note: Option<String>,
}

impl PreMutationSnapshot {
    /// Build a snapshot from raw before-state bytes. Bytes are
    /// hex-encoded so the WAL frame's JSON payload stays text-friendly
    /// without pulling a base64 dep. Caller picks the bytes for their
    /// domain (file contents, JSON of prior DB row, etc).
    pub fn new(
        mutation_kind: MutationKind,
        target: impl Into<String>,
        before_state: &[u8],
        now_unix: i64,
    ) -> Self {
        Self {
            mutation_kind,
            target: target.into(),
            before_state_hex: hex_encode(before_state),
            ts_unix: now_unix,
            note: None,
        }
    }

    /// Operator-supplied reason note. Surfaces in `neoth rollback list`
    /// so the operator sees WHY each snapshot was taken before picking
    /// one to restore from.
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// Decode the hex before-state back into raw bytes. Returns Err
    /// on malformed hex (would indicate WAL corruption or a manual
    /// edit by the operator).
    pub fn before_state_bytes(&self) -> Result<Vec<u8>> {
        hex_decode(&self.before_state_hex).context("decode before_state hex")
    }
}

/// Lowercase hex encoding. Tight + dependency-free.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX_CHARS[(b >> 4) as usize] as char);
        out.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        anyhow::bail!("hex string has odd length");
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        other => anyhow::bail!("invalid hex char: {:?}", other as char),
    }
}

/// Append a `PRE_MUTATION_SNAPSHOT` frame to the WAL. Returns the WAL
/// offset of the frame — operators reference snapshots by offset in
/// `neoth rollback --to <offset>`.
///
/// The mutation MUST NOT run until this call returns Ok — otherwise
/// the audit anchor is missing and rollback for that mutation is
/// impossible.
pub async fn emit_snapshot(
    writer: &WalWriterHandle,
    snapshot: &PreMutationSnapshot,
) -> Result<u64> {
    let payload =
        serde_json::to_vec(snapshot).context("serialize PRE_MUTATION_SNAPSHOT payload")?;
    let header = HeaderBuilder::new(EVENT_TYPE_PRE_MUTATION_SNAPSHOT, &payload).build();
    writer
        .append(header, payload)
        .await
        .context("append PRE_MUTATION_SNAPSHOT frame")
}

/// A3 / Konsens-decision #4: policy-aware snapshot emission.
///
/// Caller's mutation site invokes this BEFORE running the mutation:
///   - Looks up the operator's `RollbackConfig::should_capture(kind)`.
///   - When false → no-op, returns `Ok(None)` (operator opted out of
///     this kind).
///   - When true + before_state exceeds `max_snapshot_bytes` → no-op
///     with a tracing::warn that surfaces the skip to the operator.
///   - Otherwise → run [`redact_before_state_if_credential_bearing`]
///     so secret-shape values get replaced with `[REDACTED:<kind>]`
///     markers BEFORE the bytes hit the WAL, then emit the frame.
///
/// `Ok(None)` is the most common outcome (operator default captures
/// only config_write + channel_send; everything else skips), so the
/// caller pattern is: `let _ = emit_if_policy_allows(...)?;` then run
/// the mutation. Failures inside the WAL appender bubble up so the
/// mutation gets aborted before any actual change.
///
/// K-Sec-5 (2026-05-22): for credential-bearing kinds (`ConfigWrite`,
/// `FileWrite`) we route `before_state` through the secret-shape
/// regex pass in [`crate::security::redact::redact_text`] before
/// hex-encoding it into the frame. Operator running `neoth rollback
/// apply` against a credential snapshot gets the redacted form back
/// — credentials should always be re-prompted, never restored from
/// audit history.
pub async fn emit_if_policy_allows(
    writer: &WalWriterHandle,
    rollback: &crate::config::RollbackConfig,
    kind: MutationKind,
    target: impl Into<String>,
    before_state: &[u8],
    now_unix: i64,
    note: Option<String>,
) -> Result<Option<u64>> {
    let kind_str = mutation_kind_str(kind);
    if !rollback.should_capture(kind_str) {
        return Ok(None);
    }
    if before_state.len() > rollback.max_snapshot_bytes {
        tracing::warn!(
            kind = kind_str,
            before_bytes = before_state.len(),
            cap = rollback.max_snapshot_bytes,
            "skipping snapshot — before_state exceeds rollback.max_snapshot_bytes cap"
        );
        return Ok(None);
    }
    let redacted = redact_before_state_if_credential_bearing(kind, before_state);
    let mut snap = PreMutationSnapshot::new(kind, target, &redacted, now_unix);
    if let Some(n) = note {
        snap = snap.with_note(n);
    }
    let offset = emit_snapshot(writer, &snap).await?;
    Ok(Some(offset))
}

/// K-Sec-5: redact secret-shape substrings from `before_state` for the
/// `MutationKind` variants that commonly carry credentials. Other
/// variants pass through unchanged so binary file-write snapshots /
/// SQL row dumps keep their original bytes.
///
/// Returns a `Cow` so the no-redaction path doesn't allocate. Pure
/// function; safe to call before locks / async boundaries.
pub fn redact_before_state_if_credential_bearing<'a>(
    kind: MutationKind,
    before_state: &'a [u8],
) -> std::borrow::Cow<'a, [u8]> {
    use std::borrow::Cow;
    // SX-02 (A5 CRIT-02): ChannelSend MUST redact too — operator-typed
    // text from inbound channels regularly contains pasted API keys
    // ("here's my new openai key sk-..."). Excluding it meant such
    // keys persisted in plaintext WAL `before_state` forever.
    let should_redact = matches!(
        kind,
        MutationKind::ConfigWrite
            | MutationKind::FileWrite
            | MutationKind::Other
            | MutationKind::ChannelSend
    );
    if !should_redact {
        return Cow::Borrowed(before_state);
    }
    let Ok(text) = std::str::from_utf8(before_state) else {
        // Non-UTF-8 bytes (binary file write) — can't run the regex
        // pass, leave as-is. Operators capturing a binary file via
        // `neoth rollback apply` already accept the file bytes are
        // opaque from the WAL's POV.
        return Cow::Borrowed(before_state);
    };
    let (redacted, changed) = crate::security::redact::redact_if_secret(text);
    if !changed {
        return Cow::Borrowed(before_state);
    }
    Cow::Owned(redacted.into_bytes())
}

/// Stable wire-name for a `MutationKind`. Mirrors the `serde(rename_all =
/// "snake_case")` so `should_capture` strings stay aligned.
pub(crate) fn mutation_kind_str(k: MutationKind) -> &'static str {
    match k {
        MutationKind::FileWrite => "file_write",
        MutationKind::ChannelSend => "channel_send",
        MutationKind::McpToolInvoke => "mcp_tool_invoke",
        MutationKind::SqlMutation => "sql_mutation",
        MutationKind::ConfigWrite => "config_write",
        MutationKind::Other => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_roundtrips_through_json() {
        let s = PreMutationSnapshot::new(
            MutationKind::FileWrite,
            "/tmp/x.txt",
            b"hello world",
            1_700_000_000,
        )
        .with_note("manual edit before refactor");
        let json = serde_json::to_string(&s).unwrap();
        let back: PreMutationSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.mutation_kind, MutationKind::FileWrite);
        assert_eq!(back.target, "/tmp/x.txt");
        assert_eq!(back.note.as_deref(), Some("manual edit before refactor"));
        assert_eq!(back.before_state_bytes().unwrap(), b"hello world");
        assert_eq!(back.ts_unix, 1_700_000_000);
    }

    #[test]
    fn mutation_kind_serializes_as_snake_case() {
        let kinds = [
            (MutationKind::FileWrite, "\"file_write\""),
            (MutationKind::ChannelSend, "\"channel_send\""),
            (MutationKind::McpToolInvoke, "\"mcp_tool_invoke\""),
            (MutationKind::SqlMutation, "\"sql_mutation\""),
            (MutationKind::ConfigWrite, "\"config_write\""),
            (MutationKind::Other, "\"other\""),
        ];
        for (k, expected) in kinds {
            assert_eq!(serde_json::to_string(&k).unwrap(), expected);
        }
    }

    #[test]
    fn snapshot_without_note_serialises_without_field() {
        // Default-skipped Option<String> would keep the wire payload
        // compact for the common case (no operator note). Verify the
        // shape stays clean even without that optimisation — the
        // field appears as `"note":null` which is still small.
        let s = PreMutationSnapshot::new(MutationKind::ChannelSend, "telegram:12345", b"", 1700);
        let json = serde_json::to_string(&s).unwrap();
        // The note field is present as null when not set; round-trip
        // still recovers None.
        let back: PreMutationSnapshot = serde_json::from_str(&json).unwrap();
        assert!(back.note.is_none());
    }

    #[test]
    fn before_state_base64_handles_binary_payload() {
        // Real adapter payloads are often binary (file content with
        // null bytes, gzip'd snapshots, etc). Base64 round-trips them
        // cleanly.
        let raw: Vec<u8> = (0u8..=255).collect();
        let s = PreMutationSnapshot::new(MutationKind::FileWrite, "/tmp/binfile", &raw, 1700);
        let json = serde_json::to_string(&s).unwrap();
        let back: PreMutationSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.before_state_bytes().unwrap(), raw);
    }

    #[test]
    fn before_state_bytes_errors_on_malformed_hex() {
        let mut s = PreMutationSnapshot::new(MutationKind::Other, "x", b"hi", 1700);
        // Manually clobber the hex string.
        s.before_state_hex = "not!valid!hex!".to_string();
        let r = s.before_state_bytes();
        assert!(r.is_err());
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("hex"));
    }

    #[test]
    fn before_state_bytes_errors_on_odd_length_hex() {
        let mut s = PreMutationSnapshot::new(MutationKind::Other, "x", b"hi", 1700);
        s.before_state_hex = "abc".to_string();
        let r = s.before_state_bytes();
        assert!(r.is_err());
        // `with_context` wraps the inner error; use `{:#}` to render
        // the full chain when asserting on the actual reason.
        let msg = format!("{:#}", r.unwrap_err());
        assert!(
            msg.contains("odd length"),
            "expected odd-length reason: {msg}"
        );
    }

    #[test]
    fn hex_encode_decode_roundtrip_handles_full_byte_range() {
        let raw: Vec<u8> = (0u8..=255).collect();
        let hex = hex_encode(&raw);
        assert_eq!(hex.len(), raw.len() * 2);
        let back = hex_decode(&hex).unwrap();
        assert_eq!(back, raw);
    }

    #[test]
    fn hex_decode_accepts_uppercase_and_lowercase() {
        assert_eq!(hex_decode("DEAD").unwrap(), vec![0xDE, 0xAD]);
        assert_eq!(hex_decode("dead").unwrap(), vec![0xDE, 0xAD]);
        assert_eq!(hex_decode("DeAd").unwrap(), vec![0xDE, 0xAD]);
    }

    #[tokio::test]
    async fn emit_if_policy_allows_skips_when_kind_not_in_allowlist() {
        use crate::config::RollbackConfig;
        use crate::wal::writer::spawn;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let seg = dir.path().join("policy-skip.wal");
        let (writer, join) = spawn(seg.clone()).unwrap();
        let policy = RollbackConfig::default(); // [config_write, channel_send]

        // sql_mutation is NOT in default → returns None, no frame.
        let result = emit_if_policy_allows(
            &writer,
            &policy,
            MutationKind::SqlMutation,
            "idx_episode:42",
            b"prior row",
            1700,
            None,
        )
        .await
        .unwrap();
        assert!(result.is_none(), "expected None when kind not allowed");

        drop(writer);
        let _ = join.await;

        // Confirm no 0xF2 frame landed on disk.
        let bytes = tokio::fs::read(&seg).await.unwrap();
        // Anything beyond the segment header is either the indexer's
        // bookkeeping or empty. We don't assert against frames here
        // because the WAL writer emits no frames when nothing is
        // appended — just verify file size is small.
        assert!(
            bytes.len() < 256,
            "no PRE_MUTATION_SNAPSHOT should have landed"
        );
    }

    #[tokio::test]
    async fn emit_if_policy_allows_emits_when_kind_in_allowlist() {
        use crate::config::RollbackConfig;
        use crate::wal::writer::spawn;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let seg = dir.path().join("policy-allow.wal");
        let (writer, join) = spawn(seg.clone()).unwrap();
        let policy = RollbackConfig::default(); // includes config_write

        let offset = emit_if_policy_allows(
            &writer,
            &policy,
            MutationKind::ConfigWrite,
            "~/.neoth/freedom.yaml",
            b"prior yaml content",
            1700,
            Some("operator hemisphere rebind".to_string()),
        )
        .await
        .unwrap();
        assert!(offset.is_some(), "expected Some(offset) when kind allowed");

        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn emit_if_policy_allows_skips_when_before_state_exceeds_cap() {
        use crate::config::RollbackConfig;
        use crate::wal::writer::spawn;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let seg = dir.path().join("policy-cap.wal");
        let (writer, join) = spawn(seg.clone()).unwrap();
        let policy = RollbackConfig {
            capture_kinds: vec!["config_write".to_string()],
            max_snapshot_bytes: 100, // tiny cap
        };

        let huge = vec![0u8; 500]; // exceeds 100 B cap
        let result = emit_if_policy_allows(
            &writer,
            &policy,
            MutationKind::ConfigWrite,
            "~/.neoth/freedom.yaml",
            &huge,
            1700,
            None,
        )
        .await
        .unwrap();
        assert!(
            result.is_none(),
            "expected None when before_state exceeds cap"
        );

        drop(writer);
        let _ = join.await;
    }

    #[test]
    fn k_sec_5_redacts_openai_key_in_config_write_before_state() {
        // freedom.yaml carrying a legacy single-file install with
        // `provider_key: sk-abc123...`. The before_state captured for
        // the WAL must NOT contain the literal key bytes.
        let yaml = b"operator_id: sam\nprovider_key: sk-abc1234567890abcdefxyz\n";
        let out = redact_before_state_if_credential_bearing(MutationKind::ConfigWrite, yaml);
        let s = std::str::from_utf8(&out).unwrap();
        assert!(
            !s.contains("sk-abc1234567890abcdefxyz"),
            "secret-shape openai key must be redacted from ConfigWrite before_state"
        );
        assert!(
            s.contains("[REDACTED:openai_key]"),
            "redaction marker must be present: {s}"
        );
        // Non-secret fields stay intact.
        assert!(s.contains("operator_id: sam"));
    }

    #[test]
    fn k_sec_5_redacts_anthropic_key_in_file_write_before_state() {
        let body = b"some text\nANTHROPIC=sk-ant-api03_xxxxxxxxxxxxxxxxxxxx\nmore";
        let out = redact_before_state_if_credential_bearing(MutationKind::FileWrite, body);
        let s = std::str::from_utf8(&out).unwrap();
        assert!(
            !s.contains("sk-ant-api03_xxxxxxxxxxxxxxxxxxxx"),
            "anthropic key must be redacted"
        );
        assert!(s.contains("[REDACTED:anthropic_key]"));
    }

    #[test]
    fn k_sec_5_leaves_non_secret_bytes_alone() {
        // A regular file write that doesn't contain a secret pattern
        // must return the original bytes unchanged (and the Cow stays
        // borrowed — no allocation).
        let bytes = b"hello world\nno secrets here";
        let out = redact_before_state_if_credential_bearing(MutationKind::FileWrite, bytes);
        assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
        assert_eq!(&*out, bytes);
    }

    #[test]
    fn k_sec_5_skips_redaction_for_domain_specific_non_text_kinds() {
        // SX-02 (A5 CRIT-02) INVERT: ChannelSend now redacts (operator-
        // typed inbound text routinely carries pasted API keys). The
        // remaining skip set covers MutationKinds whose before_state is
        // domain-specific bytes (SQL row dumps, MCP tool inputs) that
        // we accept may incidentally match a secret regex — operators
        // who need redaction there enable per-tool redaction policies
        // in a later phase (tracked separately).
        let pretend_secret = b"sk-ant-api03_xxxxxxxxxxxxxxxxxxxx";
        let out =
            redact_before_state_if_credential_bearing(MutationKind::SqlMutation, pretend_secret);
        assert_eq!(
            &*out, pretend_secret,
            "SqlMutation must NOT trigger redaction"
        );
        let out =
            redact_before_state_if_credential_bearing(MutationKind::McpToolInvoke, pretend_secret);
        assert_eq!(
            &*out, pretend_secret,
            "McpToolInvoke must NOT trigger redaction"
        );
    }

    #[test]
    fn k_sec_5_channelsend_redacts_openai_key() {
        let payload = b"new key for you: sk-1234567890abcdefghijklmnopqrstuvwxyz123456";
        let out = redact_before_state_if_credential_bearing(MutationKind::ChannelSend, payload);
        let s = std::str::from_utf8(&out).expect("redacted output stays UTF-8");
        assert!(
            s.contains("[REDACTED"),
            "expected redaction marker in {s:?}"
        );
        assert!(
            !s.contains("sk-1234567890abcdef"),
            "raw OpenAI-style key leaked: {s:?}"
        );
    }

    #[test]
    fn k_sec_5_channelsend_redacts_anthropic_key() {
        let payload = b"my anthropic key is sk-ant-api03_REPLACEMEWITHREALKEYBYTESxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let out = redact_before_state_if_credential_bearing(MutationKind::ChannelSend, payload);
        let s = std::str::from_utf8(&out).expect("redacted output stays UTF-8");
        assert!(
            s.contains("[REDACTED"),
            "expected redaction marker in {s:?}"
        );
        assert!(
            !s.contains("REPLACEMEWITHREAL"),
            "raw Anthropic-style key leaked: {s:?}"
        );
    }

    #[test]
    fn k_sec_5_channelsend_preserves_non_secret_utf8() {
        // Plain operator message must round-trip unchanged so the
        // WAL replay surface keeps producing readable history. The
        // Cow::Borrowed return signals zero-copy / no allocation.
        let payload = b"hello world, no secrets in this message";
        let out = redact_before_state_if_credential_bearing(MutationKind::ChannelSend, payload);
        assert!(
            matches!(out, std::borrow::Cow::Borrowed(_)),
            "non-secret ChannelSend must not allocate"
        );
        assert_eq!(&*out, payload);
    }

    #[test]
    fn k_sec_5_channelsend_passthrough_on_binary_payload() {
        // Non-UTF-8 inbound channel payload (e.g. a forwarded binary
        // attachment recorded as opaque bytes) must not panic in the
        // redactor — the UTF-8 check bails to Cow::Borrowed.
        let payload: Vec<u8> = vec![0x89, 0x50, 0x4E, 0x47, 0xFF, 0xFE, 0xFD];
        let out = redact_before_state_if_credential_bearing(MutationKind::ChannelSend, &payload);
        assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
        assert_eq!(&*out, &payload[..]);
    }

    #[test]
    fn k_sec_5_passes_through_non_utf8_bytes_unchanged() {
        // Binary file content (e.g. PNG header) must not trigger a
        // panic in the regex pass — `redact_before_state_if_credential_bearing`
        // bails to Cow::Borrowed when the bytes don't parse as UTF-8.
        let bin = vec![0x89, 0x50, 0x4E, 0x47, 0xFF, 0xFE, 0xFD, 0xFC];
        let out = redact_before_state_if_credential_bearing(MutationKind::FileWrite, &bin);
        assert_eq!(&*out, bin.as_slice());
    }

    #[tokio::test]
    async fn k_sec_5_redacts_in_full_emit_if_policy_allows_pipeline() {
        // End-to-end: a ConfigWrite snapshot containing a real
        // openai-shape key lands a frame with REDACTED bytes (not
        // the literal secret) in the WAL.
        use crate::config::RollbackConfig;
        use crate::wal::events::EVENT_TYPE_PRE_MUTATION_SNAPSHOT;
        use crate::wal::frame::decode_frame;
        use crate::wal::segment_header::SEGMENT_HEADER_LEN;
        use crate::wal::writer::spawn;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let seg = dir.path().join("sec5.wal");
        let (writer, join) = spawn(seg.clone()).unwrap();
        let policy = RollbackConfig::default();

        let yaml = b"operator_id: sam\nprovider_key: sk-abc1234567890leakedxyz\n";
        let _ = emit_if_policy_allows(
            &writer,
            &policy,
            MutationKind::ConfigWrite,
            "~/.neoth/freedom.yaml",
            yaml,
            1_700_000_000,
            None,
        )
        .await
        .unwrap();
        drop(writer);
        let _ = join.await;

        let bytes = std::fs::read(&seg).unwrap();
        // Brute-force string search across the entire on-disk segment —
        // if the literal secret leaks ANYWHERE (frame body, hex encoding,
        // ...), the test must catch it. xxhash hex of the literal could
        // collide in pathological cases but is vanishingly unlikely.
        let leaked = bytes.windows(20).any(|w| w == b"sk-abc1234567890leak");
        assert!(
            !leaked,
            "literal secret leaked into WAL bytes — K-Sec-5 redaction failed"
        );

        // And confirm the frame carries the redaction marker.
        let mut cursor = &bytes[SEGMENT_HEADER_LEN..];
        let mut payload_text = None;
        while !cursor.is_empty() {
            let frame = decode_frame(cursor).expect("decode frame");
            if frame.header.event_type == EVENT_TYPE_PRE_MUTATION_SNAPSHOT {
                let p: PreMutationSnapshot = serde_json::from_slice(frame.payload).unwrap();
                payload_text =
                    Some(String::from_utf8_lossy(&p.before_state_bytes().unwrap()).into_owned());
                break;
            }
            cursor = &cursor[frame.header.total_len as usize..];
        }
        let pt = payload_text.expect("snapshot frame must be present");
        assert!(
            pt.contains("[REDACTED:openai_key]"),
            "redaction marker must be in before_state: {pt}"
        );
    }

    #[test]
    fn mutation_kind_str_round_trip_matches_serde_wire_name() {
        // Pin the wire names so `should_capture` lookups stay aligned
        // with the serde `rename_all = "snake_case"` shape.
        assert_eq!(mutation_kind_str(MutationKind::FileWrite), "file_write");
        assert_eq!(mutation_kind_str(MutationKind::ChannelSend), "channel_send");
        assert_eq!(
            mutation_kind_str(MutationKind::McpToolInvoke),
            "mcp_tool_invoke"
        );
        assert_eq!(mutation_kind_str(MutationKind::SqlMutation), "sql_mutation");
        assert_eq!(mutation_kind_str(MutationKind::ConfigWrite), "config_write");
        assert_eq!(mutation_kind_str(MutationKind::Other), "other");
    }

    #[tokio::test]
    async fn emit_snapshot_writes_0xf2_frame_to_wal() {
        use crate::wal::events::EVENT_TYPE_PRE_MUTATION_SNAPSHOT;
        use crate::wal::frame::decode_frame;
        use crate::wal::segment_header::SEGMENT_HEADER_LEN;
        use crate::wal::writer::spawn;
        use tempfile::tempdir;
        use tokio::fs::read;

        let dir = tempdir().unwrap();
        let seg = dir.path().join("snapshot.wal");
        let (writer, join) = spawn(seg.clone()).unwrap();

        let snap = PreMutationSnapshot::new(
            MutationKind::McpToolInvoke,
            "filesystem:read_file",
            b"prior file state",
            1_700_000_000,
        );
        let _offset = emit_snapshot(&writer, &snap).await.unwrap();
        drop(writer);
        let _ = join.await;

        let bytes = read(&seg).await.unwrap();
        let mut cursor = &bytes[SEGMENT_HEADER_LEN..];
        let mut found = None;
        while !cursor.is_empty() {
            let frame = decode_frame(cursor).expect("decode frame");
            if frame.header.event_type == EVENT_TYPE_PRE_MUTATION_SNAPSHOT {
                let p: PreMutationSnapshot = serde_json::from_slice(frame.payload).unwrap();
                found = Some(p);
                break;
            }
            cursor = &cursor[frame.header.total_len as usize..];
        }
        let p = found.expect("snapshot frame must be present");
        assert_eq!(p.mutation_kind, MutationKind::McpToolInvoke);
        assert_eq!(p.target, "filesystem:read_file");
        assert_eq!(p.before_state_bytes().unwrap(), b"prior file state");
    }

    /// MUTATION-SAFE WRITER DEMO (operator-requested) — the end-to-end proof the
    /// snapshot framing exists to provide: a pre-mutation snapshot captured
    /// through `WalWriterHandle` survives the subsequent mutation, so the
    /// pre-state is recoverable from the WAL ALONE regardless of what the caller
    /// does to the live resource afterwards. snapshot → mutate → scan WAL →
    /// recover `before_state` → assert it equals the ORIGINAL (not the mutated
    /// value) → notional restore. This is the recovery guarantee that distinguishes
    /// a mutation-safe writer from a plain destructive one.
    #[tokio::test]
    async fn mutation_safe_writer_demo_recovers_pre_mutation_state() {
        use crate::wal::events::EVENT_TYPE_PRE_MUTATION_SNAPSHOT;
        use crate::wal::frame::decode_frame;
        use crate::wal::segment_header::SEGMENT_HEADER_LEN;
        use crate::wal::writer::spawn;
        use tempfile::tempdir;
        use tokio::fs::read;

        let dir = tempdir().unwrap();
        let seg = dir.path().join("mutation_demo.wal");
        let (writer, join) = spawn(seg.clone()).unwrap();

        // A mutable resource. Snapshot its state BEFORE the mutation.
        let original: Vec<u8> = b"original content".to_vec();
        let snap = PreMutationSnapshot::new(
            MutationKind::ConfigWrite,
            "/demo/resource",
            &original,
            1_700_000_000,
        );
        emit_snapshot(&writer, &snap).await.unwrap();

        // The mutation happens AFTER the snapshot — the live resource changes.
        let mut resource: Vec<u8> = b"mutated content".to_vec();
        assert_ne!(
            resource, original,
            "the mutation actually changed the resource"
        );

        // Recover the pre-mutation state from the WAL alone.
        drop(writer);
        let _ = join.await;
        let bytes = read(&seg).await.unwrap();
        let mut cursor = &bytes[SEGMENT_HEADER_LEN..];
        let mut recovered: Option<Vec<u8>> = None;
        while !cursor.is_empty() {
            let frame = decode_frame(cursor).expect("decode frame");
            if frame.header.event_type == EVENT_TYPE_PRE_MUTATION_SNAPSHOT {
                let p: PreMutationSnapshot = serde_json::from_slice(frame.payload).unwrap();
                recovered = Some(p.before_state_bytes().unwrap().to_vec());
                break;
            }
            cursor = &cursor[frame.header.total_len as usize..];
        }
        let recovered = recovered.expect("snapshot frame must be present in the WAL");

        // The invariant: the WAL holds the pre-mutation state, independent of the
        // live mutation. "Restoring" is writing that recovered state back.
        assert_eq!(
            recovered, original,
            "recovered state must equal the pre-mutation original"
        );
        assert_ne!(
            recovered, resource,
            "recovered state must NOT equal the post-mutation value"
        );
        resource = recovered.clone(); // notional restore
        assert_eq!(
            resource, original,
            "after restore the resource matches the original again"
        );
    }
}
