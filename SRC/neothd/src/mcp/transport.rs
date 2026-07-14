//! JSON-RPC 2.0 stdio transport helpers — pure functions over byte buffers.
//!
//! MCP stdio messages are compact UTF-8 JSON, one message per line. This is
//! deliberately **not** LSP's `Content-Length` framing: the MCP transport
//! specification requires newline-delimited JSON and forbids raw embedded
//! newlines in a message.
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

/// Maximum allowed MCP message body in bytes (16 MiB). The parser rejects an
/// unterminated or delimited message as soon as it crosses this ceiling, so the
/// client's receive buffer remains bounded even for a malicious child process.
pub const MAX_MCP_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Encode one compact JSON body for MCP stdio by appending its line delimiter.
///
/// Callers pass bytes produced by `serde_json::to_vec`, so a raw newline cannot
/// occur inside the body (newlines in JSON strings are escaped as `\\n`).
pub fn frame(body: &[u8]) -> Vec<u8> {
    debug_assert!(
        !body.contains(&b'\n'),
        "MCP stdio JSON must not contain raw newlines"
    );
    let mut out = Vec::with_capacity(body.len() + 1);
    out.extend_from_slice(body);
    out.push(b'\n');
    out
}

/// Parse one newline-delimited MCP stdio message from a byte buffer. Returns
/// `(message_body, bytes_consumed)` on success, or `None` until the delimiter
/// arrives. Multiple buffered messages are consumed one at a time.
///
/// Pure function over the byte slice — the caller owns buffering +
/// drains `bytes_consumed` after a successful parse.
pub fn parse_frame(buf: &[u8]) -> Result<Option<(Vec<u8>, usize)>, FrameError> {
    let Some(line_end) = buf.iter().position(|byte| *byte == b'\n') else {
        if buf.len() > MAX_MCP_FRAME_BYTES {
            return Err(FrameError::FrameTooLarge(buf.len()));
        }
        return Ok(None);
    };
    if line_end > MAX_MCP_FRAME_BYTES {
        return Err(FrameError::FrameTooLarge(line_end));
    }
    if line_end == 0 {
        return Err(FrameError::EmptyMessage);
    }
    // JSON permits trailing whitespace, so a CRLF sender remains harmlessly
    // interoperable: the `\r` stays in the body and serde_json accepts it.
    Ok(Some((buf[..line_end].to_vec(), line_end + 1)))
}

/// Errors the framer can produce.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("empty MCP stdio message")]
    EmptyMessage,
    #[error("MCP stdio message is too large: {0} bytes exceeds limit")]
    FrameTooLarge(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_appends_exactly_one_newline() {
        let body = b"{\"jsonrpc\":\"2.0\"}";
        let framed = frame(body);
        assert_eq!(framed, b"{\"jsonrpc\":\"2.0\"}\n");
    }

    #[test]
    fn parse_frame_returns_none_until_newline() {
        let r = parse_frame(b"{\"jsonrpc\":\"2.0\"}").unwrap();
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
    fn parse_frame_consumes_only_first_of_multiple_messages() {
        let bytes = b"{\"id\":1}\n{\"id\":2}\n";
        let (first, consumed) = parse_frame(bytes).unwrap().unwrap();
        assert_eq!(first, b"{\"id\":1}");
        let (second, consumed_second) = parse_frame(&bytes[consumed..]).unwrap().unwrap();
        assert_eq!(second, b"{\"id\":2}");
        assert_eq!(consumed + consumed_second, bytes.len());
    }

    #[test]
    fn parse_frame_rejects_oversized_undelimited_message() {
        let bytes = vec![b'x'; MAX_MCP_FRAME_BYTES + 1];
        assert!(matches!(
            parse_frame(&bytes),
            Err(FrameError::FrameTooLarge(n)) if n == MAX_MCP_FRAME_BYTES + 1
        ));
    }

    #[test]
    fn parse_frame_accepts_exactly_at_limit() {
        let mut bytes = vec![b'x'; MAX_MCP_FRAME_BYTES];
        bytes.push(b'\n');
        let (body, consumed) = parse_frame(&bytes).unwrap().unwrap();
        assert_eq!(body.len(), MAX_MCP_FRAME_BYTES);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn parse_frame_rejects_empty_message() {
        assert!(matches!(parse_frame(b"\n"), Err(FrameError::EmptyMessage)));
    }

    #[test]
    fn parse_frame_tolerates_crlf_as_json_whitespace() {
        let (body, consumed) = parse_frame(b"{}\r\n").unwrap().unwrap();
        assert_eq!(body, b"{}\r");
        assert_eq!(consumed, 4);
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value, serde_json::json!({}));
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
