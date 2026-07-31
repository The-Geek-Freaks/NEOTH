//! Bounded provider-response primitives.
//!
//! Remote and OpenAI-compatible endpoints are untrusted byte sources even
//! after returning HTTP 2xx. These helpers cap allocation before JSON parsing
//! and before an unterminated streaming frame can grow without bound. Errors
//! retain only domain-separated digest evidence, never response bytes.

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
