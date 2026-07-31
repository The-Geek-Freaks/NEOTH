//! Bounded provider-response primitives.
//!
//! Remote and OpenAI-compatible endpoints are untrusted byte sources even
//! after returning HTTP 2xx. These helpers cap allocation before JSON parsing
//! and before an unterminated streaming frame can grow without bound. Errors
//! retain only domain-separated digest evidence, never response bytes.
//!
//! Dropping the `reqwest` error source on a failed read is deliberate, not an
//! oversight: the chain is provider-controlled and has echoed request URLs and
//! headers. Adapters adopting these helpers must not add the source back for
//! nicer diagnostics.

use anyhow::Result;
use futures_util::StreamExt;
use serde::de::DeserializeOwned;

pub(crate) const MAX_SUCCESS_JSON_BODY_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_SSE_FRAME_BYTES: usize = 1024 * 1024;

pub(crate) fn byte_evidence(
    domain: &'static [u8],
    slices: &[&[u8]],
    input_truncated: bool,
) -> String {
    evidence("body", domain, slices, input_truncated)
}

pub(crate) fn frame_evidence(
    domain: &'static [u8],
    slices: &[&[u8]],
    input_truncated: bool,
) -> String {
    evidence("frame", domain, slices, input_truncated)
}

pub(crate) fn stream_evidence(
    domain: &'static [u8],
    slices: &[&[u8]],
    input_truncated: bool,
) -> String {
    evidence("stream", domain, slices, input_truncated)
}

fn evidence(
    label: &'static str,
    domain: &'static [u8],
    slices: &[&[u8]],
    input_truncated: bool,
) -> String {
    let evidence =
        crate::security::redact::bounded_audit_digest_bytes(domain, slices, input_truncated);
    format!(
        "{label}_sha256={} truncated={}",
        evidence.sha256, evidence.truncated
    )
}

/// Reads a non-2xx provider body under a hard cap and keeps only
/// domain-separated digest evidence.
///
/// Error envelopes are gateway-controlled, may echo request secrets, and are
/// the one body an adapter reads on a path where nothing downstream needs the
/// bytes. Callers surface the status plus this digest.
pub(crate) async fn error_body_evidence(
    response: reqwest::Response,
    evidence_domain: &'static [u8],
    max_bytes: usize,
) -> String {
    error_body_with_evidence(response, evidence_domain, max_bytes)
        .await
        .evidence
}

/// A capped error body plus its digest.
///
/// The body field is named for its only sanctioned use: classifying the
/// envelope (a policy refusal, a typed vendor error code). It is never what an
/// error message prints — callers surface `evidence`.
///
/// If the body was truncated at the cap, a marker beyond the cap is simply not
/// seen and the caller falls through to its generic branch. That is deliberate:
/// the size bound outranks classification fidelity.
#[must_use]
pub(crate) struct BoundedErrorBody {
    pub(crate) classification_text: String,
    pub(crate) evidence: String,
}

pub(crate) async fn error_body_with_evidence(
    response: reqwest::Response,
    evidence_domain: &'static [u8],
    max_bytes: usize,
) -> BoundedErrorBody {
    let mut body = Vec::with_capacity(max_bytes.min(8 * 1024));
    let mut truncated = false;
    let mut chunks = response.bytes_stream();
    while let Some(next) = chunks.next().await {
        let Ok(chunk) = next else {
            truncated = true;
            break;
        };
        let remaining = max_bytes.saturating_sub(body.len());
        if chunk.len() > remaining {
            body.extend_from_slice(&chunk[..remaining]);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }
    let evidence = byte_evidence(evidence_domain, &[&body], truncated);
    BoundedErrorBody {
        classification_text: String::from_utf8(body)
            .unwrap_or_else(|invalid| String::from_utf8_lossy(invalid.as_bytes()).into_owned()),
        evidence,
    }
}

pub(crate) async fn decode_json<T: DeserializeOwned>(
    response: reqwest::Response,
    adapter_name: &'static str,
    evidence_domain: &'static [u8],
    max_bytes: usize,
) -> Result<T> {
    let mut body = Vec::with_capacity(max_bytes.min(8 * 1024));
    let mut chunks = response.bytes_stream();
    while let Some(next) = chunks.next().await {
        let chunk = match next {
            Ok(chunk) => chunk,
            Err(_) => {
                let evidence = byte_evidence(evidence_domain, &[&body], true);
                anyhow::bail!("{adapter_name}: successful response body read failed ({evidence})");
            }
        };
        let remaining = max_bytes.saturating_sub(body.len());
        if chunk.len() > remaining {
            let evidence = byte_evidence(evidence_domain, &[&body, &chunk], true);
            anyhow::bail!(
                "{adapter_name}: successful response body exceeded {max_bytes} bytes \
                 ({evidence})"
            );
        }
        body.extend_from_slice(&chunk);
    }

    serde_json::from_slice(&body).map_err(|error| {
        let evidence = byte_evidence(evidence_domain, &[&body], false);
        anyhow::anyhow!(
            "{adapter_name}: malformed successful JSON response at line {} column {} \
             ({evidence})",
            error.line(),
            error.column()
        )
    })
}

/// A capped read from a local byte source plus whether the cap cut it short.
pub(crate) struct BoundedRead {
    pub(crate) bytes: Vec<u8>,
    pub(crate) truncated: bool,
}

/// Reads at most `max_bytes` from a subprocess pipe or PTY.
///
/// A governed subprocess is closer to home than a remote endpoint, but its
/// output is still model-driven and a hung or hostile child can produce it
/// faster than we consume it. Stopping at the cap keeps the diagnostic while
/// refusing to hold an unbounded copy.
pub(crate) async fn read_bounded<R>(
    reader: &mut R,
    max_bytes: usize,
) -> std::io::Result<BoundedRead>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut bytes = Vec::new();
    let read = reader
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .await?;
    let truncated = read > max_bytes;
    if truncated {
        bytes.truncate(max_bytes);
    }
    Ok(BoundedRead { bytes, truncated })
}

/// Reads one newline-terminated line, refusing to grow past `max_bytes`.
///
/// `tokio`'s `Lines` has no ceiling: a child that never emits `\n` makes it
/// allocate until the process dies. Returns `Ok(None)` at EOF with nothing
/// buffered; a final line without its newline is returned like any other.
pub(crate) async fn read_bounded_line<R>(
    reader: &mut R,
    adapter_name: &'static str,
    evidence_domain: &'static [u8],
    max_bytes: usize,
) -> Result<Option<Vec<u8>>>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    use tokio::io::AsyncBufReadExt;

    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok((!line.is_empty()).then_some(line));
        }
        let (segment, consumed, complete) = match available.iter().position(|byte| *byte == b'\n') {
            Some(newline) => (&available[..newline], newline + 1, true),
            None => (available, available.len(), false),
        };
        if segment.len() > max_bytes.saturating_sub(line.len()) {
            let evidence = frame_evidence(evidence_domain, &[&line, segment], true);
            reader.consume(consumed);
            anyhow::bail!("{adapter_name}: output line exceeded {max_bytes} bytes ({evidence})");
        }
        line.extend_from_slice(segment);
        reader.consume(consumed);
        if complete {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Some(line));
        }
    }
}

pub(crate) fn append_frame_segment(
    buffer: &mut Vec<u8>,
    segment: &[u8],
    adapter_name: &'static str,
    evidence_domain: &'static [u8],
    max_bytes: usize,
) -> Result<()> {
    if segment.len() > max_bytes.saturating_sub(buffer.len()) {
        let evidence = frame_evidence(evidence_domain, &[buffer.as_slice(), segment], true);
        anyhow::bail!("{adapter_name}: streaming frame exceeded {max_bytes} bytes ({evidence})");
    }
    buffer.extend_from_slice(segment);
    Ok(())
}

pub(crate) fn frame_utf8<'a>(
    bytes: &'a [u8],
    adapter_name: &'static str,
    evidence_domain: &'static [u8],
) -> Result<&'a str> {
    std::str::from_utf8(bytes).map_err(|_| {
        let evidence = frame_evidence(evidence_domain, &[bytes], false);
        anyhow::anyhow!("{adapter_name}: streaming frame is not valid UTF-8 ({evidence})")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_frame_accepts_exact_limit_and_rejects_next_byte_without_echo() {
        let secret = b"secret-frame";
        let mut buffer = Vec::new();
        append_frame_segment(&mut buffer, secret, "fixture", b"frame/v1", secret.len())
            .expect("exact frame limit");

        let error = append_frame_segment(&mut buffer, b"x", "fixture", b"frame/v1", secret.len())
            .expect_err("one byte over the frame limit must fail");
        let message = error.to_string();
        assert!(message.contains("frame_sha256="));
        assert!(message.contains("truncated=true"));
        assert!(!message.contains("secret-frame"));
    }

    #[test]
    fn frame_utf8_allows_codepoint_split_across_transport_chunks() {
        let mut buffer = Vec::new();
        let encoded = "🦀".as_bytes();
        append_frame_segment(&mut buffer, &encoded[..2], "fixture", b"frame/v1", 8).unwrap();
        append_frame_segment(&mut buffer, &encoded[2..], "fixture", b"frame/v1", 8).unwrap();

        assert_eq!(frame_utf8(&buffer, "fixture", b"frame/v1").unwrap(), "🦀");
    }

    #[tokio::test]
    async fn read_bounded_keeps_the_cap_and_reports_truncation() {
        let mut exact = &b"12345"[..];
        let read = read_bounded(&mut exact, 5).await.expect("exact limit");
        assert_eq!(read.bytes, b"12345");
        assert!(!read.truncated);

        let mut over = &b"123456"[..];
        let read = read_bounded(&mut over, 5).await.expect("one byte over");
        assert_eq!(read.bytes, b"12345");
        assert!(read.truncated);
    }

    #[tokio::test]
    async fn bounded_lines_split_on_newline_and_reject_an_endless_one() {
        use tokio::io::BufReader;

        let mut reader = BufReader::new(&b"first\r\nsecond"[..]);
        let first = read_bounded_line(&mut reader, "fixture", b"line/v1", 64)
            .await
            .expect("first line")
            .expect("some");
        assert_eq!(first, b"first");
        // A final line without its newline is still delivered.
        let second = read_bounded_line(&mut reader, "fixture", b"line/v1", 64)
            .await
            .expect("residual line")
            .expect("some");
        assert_eq!(second, b"second");
        assert!(
            read_bounded_line(&mut reader, "fixture", b"line/v1", 64)
                .await
                .expect("eof")
                .is_none()
        );

        let secret = b"secret-line-content";
        let endless = [secret.as_slice(), &[b'x'; 64]].concat();
        let message = read_bounded_line(&mut endless.as_slice(), "fixture", b"line/v1", 16)
            .await
            .expect_err("a line with no newline must hit the cap")
            .to_string();
        assert!(message.contains("output line exceeded"));
        assert!(message.contains("frame_sha256="));
        assert!(!message.contains("secret-line-content"));
    }

    #[test]
    fn invalid_utf8_error_contains_only_digest_evidence() {
        let bytes = [0xff, b's', b'e', b'c', b'r', b'e', b't'];
        let message = frame_utf8(&bytes, "fixture", b"frame/v1")
            .expect_err("invalid UTF-8")
            .to_string();

        assert!(message.contains("frame_sha256="));
        assert!(!message.contains("secret"));
    }
}
