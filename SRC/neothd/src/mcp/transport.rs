//! JSON-RPC 2.0 framing helpers — pure functions over byte buffers.
//!
//! MCP servers exchange JSON-RPC messages over stdio. Each message is
//! framed with a `Content-Length: N\r\n\r\n` header followed by N bytes
//! of JSON body. The Microsoft LSP family uses the same framing — MCP
//! servers reuse it for transport symmetry.
//!
//! This module owns the framing + serde-typed request/response structs
//! that the client uses. No I/O happens here so the framing logic is
//! trivially unit-testable.

use serde::{Deserialize, Serialize};

/// A JSON-RPC 2.0 request.
#[derive(Clone, Debug, Serialize)]
pub struct JsonRpcRequest<'a, P> {
    pub jsonrpc: &'a str,
    pub id: u64,
    pub method: &'a str,
    pub params: P,
}

impl<'a, P: Serialize> JsonRpcRequest<'a, P> {
    pub fn new(id: u64, method: &'a str, params: P) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            method,
            params,
        }
    }
}

/// JSON-RPC 2.0 response — either `result` OR `error` is present.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error object.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub data: Option<serde_json::Value>,
}

/// Frame a JSON body with the `Content-Length` header per LSP/MCP spec.
pub fn frame(body: &[u8]) -> Vec<u8> {
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    let mut out = Vec::with_capacity(header.len() + body.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(body);
    out
}

/// Parse a framed message from a byte buffer. Returns `(message_body,
/// bytes_consumed)` on success, or `None` if the buffer doesn't yet
/// contain a complete frame. Returns `Err` if the header is malformed.
///
/// Pure function over the byte slice — the caller owns buffering +
/// drains `bytes_consumed` after a successful parse.
pub fn parse_frame(buf: &[u8]) -> Result<Option<(Vec<u8>, usize)>, FrameError> {
    let header_end = match find_double_crlf(buf) {
        Some(end) => end,
        None => return Ok(None), // header not yet complete
    };
    let header_bytes = &buf[..header_end];
    let header_str = std::str::from_utf8(header_bytes).map_err(|_| FrameError::HeaderNotUtf8)?;
    let mut content_length: Option<usize> = None;
    for line in header_str.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, ':');
        let key = parts.next().unwrap_or("").trim();
        let val = parts.next().ok_or_else(|| {
            FrameError::HeaderMalformed(format!("missing colon in line {line:?}"))
        })?;
        if key.eq_ignore_ascii_case("Content-Length") {
            content_length =
                Some(val.trim().parse().map_err(|e| {
                    FrameError::HeaderMalformed(format!("bad Content-Length: {e}"))
                })?);
        }
    }
    let content_length = content_length
        .ok_or_else(|| FrameError::HeaderMalformed("missing Content-Length".into()))?;
    let body_start = header_end + 4;
    let body_end = body_start + content_length;
    if buf.len() < body_end {
        return Ok(None); // body not yet complete
    }
    let body = buf[body_start..body_end].to_vec();
    Ok(Some((body, body_end)))
}

/// Errors the framer can produce.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("header bytes are not valid UTF-8")]
    HeaderNotUtf8,
    #[error("malformed header: {0}")]
    HeaderMalformed(String),
}

/// Find the index of the `\r\n\r\n` sequence that terminates the
/// header block. Returns `None` if not yet present.
fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    const NEEDLE: &[u8] = b"\r\n\r\n";
    if buf.len() < NEEDLE.len() {
        return None;
    }
    (0..=buf.len() - NEEDLE.len()).find(|&i| &buf[i..i + NEEDLE.len()] == NEEDLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_prepends_content_length_header() {
        let body = b"{\"jsonrpc\":\"2.0\"}";
        let framed = frame(body);
        let text = String::from_utf8(framed).unwrap();
        assert!(text.starts_with("Content-Length: 17\r\n\r\n"));
        assert!(text.ends_with("{\"jsonrpc\":\"2.0\"}"));
    }

    #[test]
    fn parse_frame_returns_none_on_incomplete_header() {
        let r = parse_frame(b"Content-Length: 1").unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn parse_frame_returns_none_on_incomplete_body() {
        let r = parse_frame(b"Content-Length: 10\r\n\r\nhalfbody").unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn parse_frame_returns_body_and_consumed_count() {
        let body = b"{\"hello\":1}";
        let framed = frame(body);
        let (parsed, consumed) = parse_frame(&framed).unwrap().unwrap();
        assert_eq!(parsed, body);
        assert_eq!(consumed, framed.len());
    }

    #[test]
    fn parse_frame_tolerates_multiple_headers() {
        let mut framed = b"Content-Length: 2\r\nContent-Type: application/json\r\n\r\n{}".to_vec();
        let (body, _) = parse_frame(&framed).unwrap().unwrap();
        assert_eq!(body, b"{}");
        // Ensure the second-header order doesn't break parsing.
        framed = b"Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}".to_vec();
        let (body2, _) = parse_frame(&framed).unwrap().unwrap();
        assert_eq!(body2, b"{}");
    }

    #[test]
    fn parse_frame_errors_on_missing_content_length() {
        let r = parse_frame(b"Content-Type: x\r\n\r\n{}");
        assert!(matches!(r, Err(FrameError::HeaderMalformed(_))));
    }

    #[test]
    fn parse_frame_errors_on_bad_content_length_value() {
        let r = parse_frame(b"Content-Length: abc\r\n\r\n{}");
        assert!(matches!(r, Err(FrameError::HeaderMalformed(_))));
    }

    #[test]
    fn request_struct_serialises_with_jsonrpc_2_0() {
        #[derive(Serialize)]
        struct EmptyParams {}
        let req = JsonRpcRequest::new(1, "tools/list", EmptyParams {});
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"method\":\"tools/list\""));
        assert!(json.contains("\"id\":1"));
    }

    #[test]
    fn response_with_result_deserialises_cleanly() {
        let body = r#"{"jsonrpc":"2.0","id":42,"result":{"tools":[]}}"#;
        let resp: JsonRpcResponse = serde_json::from_str(body).unwrap();
        assert_eq!(resp.id, 42);
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn response_with_error_deserialises_cleanly() {
        let body =
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}"#;
        let resp: JsonRpcResponse = serde_json::from_str(body).unwrap();
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32601);
        assert_eq!(err.message, "Method not found");
    }

    #[test]
    fn round_trip_frame_then_parse_yields_original_body() {
        let req_body = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0", "id": 7, "method": "ping", "params": {}
        }))
        .unwrap();
        let framed = frame(&req_body);
        let (parsed, _) = parse_frame(&framed).unwrap().unwrap();
        assert_eq!(parsed, req_body);
    }
}
