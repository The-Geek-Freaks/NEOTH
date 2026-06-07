//! AWS Signature Version 4 — hand-rolled signing helper (C-3 Phase 2,
//! Session 14).
//!
//! NEOTH deliberately does NOT pull in `aws-sigv4` or the full
//! `aws-sdk-bedrockruntime` SDK family — both bring 25+ transitive
//! crates including a second hyper version and `aws-smithy-*` runtime
//! plumbing. The signing protocol itself is ~60 LOC of hash chaining;
//! `sha2` + `hmac` are already in NEOTH's dep tree (Phase 33b HMAC
//! compaction).
//!
//! Reference: <https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html>
//!
//! The six SigV4 steps implemented here:
//!
//!   1. Canonical request: `METHOD\nURI\nQUERY\nHEADERS\nSIGNED\nHASH`
//!   2. String to sign: `ALGORITHM\nTIMESTAMP\nSCOPE\nHASH(canonical)`
//!   3. Signing key derivation: HMAC chain over (secret, date, region,
//!      service, "aws4_request")
//!   4. Signature: HMAC-SHA256(kSigning, string_to_sign)
//!   5. Authorization header: `AWS4-HMAC-SHA256 Credential=…,
//!      SignedHeaders=…, Signature=…`
//!   6. Header injection: caller threads result into outbound request
//!
//! Security posture (per Session-14 security-auditor review):
//!
//!   - All derived keys use `Zeroizing<Vec<u8>>` (guardrail #6) so memory
//!     hygiene is automatic on scope exit — no manual zeroize calls
//!     needed.
//!   - Body is always hashed (`x-amz-content-sha256` always set).
//!     `UNSIGNED-PAYLOAD` is never used — Bedrock Runtime requires the
//!     full body hash.
//!   - `x-amz-security-token` is signed when present (replay-attack
//!     protection — guardrail #9).
//!   - Authorization header is built in-place but the value itself is
//!     a derived signature (not a raw secret), so plain `String` is
//!     acceptable as long as the WAL log strips it (see
//!     `strip_sensitive_headers` in the Bedrock adapter).

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::aws_credentials::AwsCredentials;

type HmacSha256 = Hmac<Sha256>;

/// Signed headers returned by [`sign`]. The caller threads each into the
/// outbound `reqwest::Request`. Fields stay as plain `String` because
/// they are derived signatures, not raw credentials.
#[derive(Debug, Clone)]
pub struct SignedHeaders {
    /// Full `Authorization: AWS4-HMAC-SHA256 …` value.
    pub authorization: String,
    /// ISO-8601 basic-format timestamp: `YYYYMMDDTHHmmssZ`.
    pub x_amz_date: String,
    /// Hex SHA256 of the request body (or empty-string hash if no body).
    pub x_amz_content_sha256: String,
    /// Forwarded session token when credentials are temporary. None for
    /// long-lived IAM keys.
    pub x_amz_security_token: Option<String>,
}

/// Sign an outbound HTTP request per SigV4.
///
/// Inputs:
///   - `method`: HTTP verb, uppercase (`POST`, `GET`, …)
///   - `host`: bare hostname, no scheme, no port (e.g.
///     `bedrock-runtime.us-east-1.amazonaws.com`)
///   - `path`: URI path including leading slash (e.g.
///     `/model/anthropic.claude-3-5-sonnet-20241022-v2:0/converse`)
///   - `query`: pre-canonicalised query string (empty for Bedrock
///     Converse; non-empty for S3-style operations)
///   - `body`: full request body, used to derive
///     `x-amz-content-sha256`. Pass an empty slice for GET / DELETE
///     requests.
///   - `region`: AWS region (`us-east-1`, `eu-central-1`, …)
///   - `service`: AWS service name (`bedrock` for Bedrock Runtime —
///     **not** `bedrock-runtime`)
///   - `credentials`: resolved [`AwsCredentials`]
///   - `now`: signing timestamp. Must be within ±5 minutes of AWS
///     server clock or the request is rejected.
///
/// 9 arguments — each is protocol-required by the SigV4 canonical-request
/// definition; bundling them into a struct would only push the same
/// fields one level deeper without reducing complexity.
#[allow(clippy::too_many_arguments)]
pub fn sign(
    method: &str,
    host: &str,
    path: &str,
    query: &str,
    body: &[u8],
    region: &str,
    service: &str,
    credentials: &AwsCredentials,
    now: DateTime<Utc>,
) -> SignedHeaders {
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_str = now.format("%Y%m%d").to_string();
    let body_hash = hex::encode(Sha256::digest(body));

    // Build the headers that go into the canonical request. SigV4 requires
    // host + x-amz-date + x-amz-content-sha256 at minimum; security token
    // joins when present.
    let mut signed: Vec<(String, String)> = vec![
        ("host".to_string(), host.to_string()),
        ("x-amz-content-sha256".to_string(), body_hash.clone()),
        ("x-amz-date".to_string(), amz_date.clone()),
    ];
    let session_token_value = credentials
        .session_token
        .as_ref()
        .map(|t| t.expose().to_string());
    if let Some(token) = &session_token_value {
        signed.push(("x-amz-security-token".to_string(), token.clone()));
    }

    // Canonical headers are sorted alphabetically by lowercase header name.
    signed.sort_by(|a, b| a.0.cmp(&b.0));
    let canonical_headers = signed
        .iter()
        .map(|(k, v)| format!("{k}:{v}\n"))
        .collect::<String>();
    let signed_headers_str = signed
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    // SigV4 canonical URI = AWS UriEncode of the path (preserve '/').
    // Bedrock model ids carry a ':' (`…-v2:0`); without encoding it the
    // canonical request mismatches what AWS recomputes from the received
    // path → SignatureDoesNotMatch (the wire keeps the raw ':' — the
    // `url` crate doesn't encode it — and AWS UriEncodes the received
    // path the same single way, matching this `%3A`).
    let canonical_uri = uri_encode_path(path);
    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{query}\n{canonical_headers}\n{signed_headers_str}\n{body_hash}"
    );

    let scope = format!("{date_str}/{region}/{service}/aws4_request");
    let canonical_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{canonical_hash}");

    let signing_key = derive_signing_key(
        credentials.secret_access_key.expose(),
        &date_str,
        region,
        service,
    );
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        access_key = credentials.access_key_id.expose(),
        scope = scope,
        signed_headers = signed_headers_str,
    );

    SignedHeaders {
        authorization,
        x_amz_date: amz_date,
        x_amz_content_sha256: body_hash,
        x_amz_security_token: session_token_value,
    }
}

/// SigV4 signing-key chain: HMAC over (secret, date, region, service,
/// "aws4_request"). All intermediate buffers live in `Zeroizing`, so
/// each goes through `zeroize::Zeroize` on scope exit — guardrail #6
/// from the Session-14 security-auditor review.
fn derive_signing_key(
    secret_access_key: &str,
    date: &str,
    region: &str,
    service: &str,
) -> Zeroizing<Vec<u8>> {
    let k_secret = Zeroizing::new(format!("AWS4{secret_access_key}").into_bytes());
    let k_date = Zeroizing::new(hmac_sha256(&k_secret, date.as_bytes()));
    let k_region = Zeroizing::new(hmac_sha256(&k_date, region.as_bytes()));
    let k_service = Zeroizing::new(hmac_sha256(&k_region, service.as_bytes()));
    Zeroizing::new(hmac_sha256(&k_service, b"aws4_request"))
}

/// AWS `UriEncode` for a path component, `encodeSlash = false`: keep the
/// RFC 3986 unreserved set (`A-Za-z0-9-._~`) plus `/` verbatim, and
/// percent-encode every other byte as uppercase hex. Operates on bytes so
/// multibyte UTF-8 is encoded per-byte (matching the AWS SigV4 test-suite
/// `get-utf8` vector `/ሴ` → `/%E1%88%B4`).
fn uri_encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for &b in path.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(hex_upper(b >> 4));
                out.push(hex_upper(b & 0x0f));
            }
        }
    }
    out
}

/// Map a 0..=15 nibble to its uppercase hex digit.
fn hex_upper(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'A' + (nibble - 10)) as char,
    }
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretString;
    use chrono::TimeZone;

    fn fixture_creds() -> AwsCredentials {
        AwsCredentials {
            access_key_id: SecretString::new("AKIDEXAMPLE".into()),
            secret_access_key: SecretString::new("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into()),
            session_token: None,
        }
    }

    fn fixture_time() -> DateTime<Utc> {
        // 2015-08-30T12:36:00Z — the canonical AWS docs example used in
        // their reference test vectors.
        Utc.with_ymd_and_hms(2015, 8, 30, 12, 36, 0).unwrap()
    }

    #[test]
    fn empty_body_hash_matches_known_sha256() {
        // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = hex::encode(Sha256::digest(b""));
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn signing_key_derivation_is_deterministic() {
        let k1 = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "iam",
        );
        let k2 = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "iam",
        );
        assert_eq!(&k1[..], &k2[..]);
        assert_eq!(k1.len(), 32, "HMAC-SHA256 output must be 32 bytes");
    }

    #[test]
    fn signing_key_changes_with_region() {
        let k_east = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "iam",
        );
        let k_west = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-west-2",
            "iam",
        );
        assert_ne!(&k_east[..], &k_west[..]);
    }

    #[test]
    fn signing_key_changes_with_service() {
        let k_iam = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "iam",
        );
        let k_bedrock = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "bedrock",
        );
        assert_ne!(&k_iam[..], &k_bedrock[..]);
    }

    #[test]
    fn authorization_header_carries_aws4_hmac_prefix() {
        let signed = sign(
            "POST",
            "bedrock-runtime.us-east-1.amazonaws.com",
            "/model/test-model/converse",
            "",
            b"{}",
            "us-east-1",
            "bedrock",
            &fixture_creds(),
            fixture_time(),
        );
        assert!(signed.authorization.starts_with("AWS4-HMAC-SHA256 "));
    }

    #[test]
    fn authorization_header_contains_credential_scope() {
        let signed = sign(
            "POST",
            "bedrock-runtime.us-east-1.amazonaws.com",
            "/model/test/converse",
            "",
            b"{}",
            "us-east-1",
            "bedrock",
            &fixture_creds(),
            fixture_time(),
        );
        assert!(
            signed
                .authorization
                .contains("Credential=AKIDEXAMPLE/20150830/us-east-1/bedrock/aws4_request")
        );
    }

    #[test]
    fn signed_headers_list_is_alphabetical() {
        let signed = sign(
            "POST",
            "bedrock-runtime.us-east-1.amazonaws.com",
            "/model/test/converse",
            "",
            b"{}",
            "us-east-1",
            "bedrock",
            &fixture_creds(),
            fixture_time(),
        );
        // host < x-amz-content-sha256 < x-amz-date — alphabetical.
        assert!(
            signed
                .authorization
                .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date")
        );
    }

    #[test]
    fn x_amz_date_uses_iso_basic_format() {
        let signed = sign(
            "POST",
            "bedrock-runtime.us-east-1.amazonaws.com",
            "/model/test/converse",
            "",
            b"{}",
            "us-east-1",
            "bedrock",
            &fixture_creds(),
            fixture_time(),
        );
        assert_eq!(signed.x_amz_date, "20150830T123600Z");
    }

    #[test]
    fn body_hash_is_sha256_of_payload() {
        let body = br#"{"messages":[]}"#;
        let signed = sign(
            "POST",
            "bedrock-runtime.us-east-1.amazonaws.com",
            "/model/test/converse",
            "",
            body,
            "us-east-1",
            "bedrock",
            &fixture_creds(),
            fixture_time(),
        );
        let expected = hex::encode(Sha256::digest(body));
        assert_eq!(signed.x_amz_content_sha256, expected);
    }

    #[test]
    fn session_token_threads_into_signed_headers_when_present() {
        let creds = AwsCredentials {
            access_key_id: SecretString::new("AKIDEXAMPLE".into()),
            secret_access_key: SecretString::new("secret".into()),
            session_token: Some(SecretString::new("session-token-blob".into())),
        };
        let signed = sign(
            "POST",
            "bedrock-runtime.us-east-1.amazonaws.com",
            "/model/test/converse",
            "",
            b"{}",
            "us-east-1",
            "bedrock",
            &creds,
            fixture_time(),
        );
        assert_eq!(
            signed.x_amz_security_token,
            Some("session-token-blob".to_string())
        );
        // SignedHeaders must include x-amz-security-token in alphabetical
        // position (after the two existing x-amz-* headers).
        assert!(
            signed.authorization.contains(
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
            )
        );
    }

    #[test]
    fn session_token_absent_when_none() {
        let signed = sign(
            "POST",
            "bedrock-runtime.us-east-1.amazonaws.com",
            "/model/test/converse",
            "",
            b"{}",
            "us-east-1",
            "bedrock",
            &fixture_creds(),
            fixture_time(),
        );
        assert!(signed.x_amz_security_token.is_none());
        assert!(!signed.authorization.contains("x-amz-security-token"));
    }

    #[test]
    fn signature_changes_when_body_changes() {
        let body_a = b"{}";
        let body_b = br#"{"messages":[]}"#;
        let sig_a = sign(
            "POST",
            "bedrock-runtime.us-east-1.amazonaws.com",
            "/model/test/converse",
            "",
            body_a,
            "us-east-1",
            "bedrock",
            &fixture_creds(),
            fixture_time(),
        );
        let sig_b = sign(
            "POST",
            "bedrock-runtime.us-east-1.amazonaws.com",
            "/model/test/converse",
            "",
            body_b,
            "us-east-1",
            "bedrock",
            &fixture_creds(),
            fixture_time(),
        );
        // Different bodies → different content-sha256 → different signatures.
        // Replay-attack protection (guardrail #9).
        assert_ne!(sig_a.authorization, sig_b.authorization);
        assert_ne!(sig_a.x_amz_content_sha256, sig_b.x_amz_content_sha256);
    }

    #[test]
    fn signature_changes_when_timestamp_changes() {
        let t1 = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let t2 = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 1).unwrap();
        let sig1 = sign(
            "POST",
            "bedrock-runtime.us-east-1.amazonaws.com",
            "/model/test/converse",
            "",
            b"{}",
            "us-east-1",
            "bedrock",
            &fixture_creds(),
            t1,
        );
        let sig2 = sign(
            "POST",
            "bedrock-runtime.us-east-1.amazonaws.com",
            "/model/test/converse",
            "",
            b"{}",
            "us-east-1",
            "bedrock",
            &fixture_creds(),
            t2,
        );
        assert_ne!(sig1.authorization, sig2.authorization);
    }

    #[test]
    fn signature_changes_when_path_changes() {
        let s1 = sign(
            "POST",
            "bedrock-runtime.us-east-1.amazonaws.com",
            "/model/a/converse",
            "",
            b"{}",
            "us-east-1",
            "bedrock",
            &fixture_creds(),
            fixture_time(),
        );
        let s2 = sign(
            "POST",
            "bedrock-runtime.us-east-1.amazonaws.com",
            "/model/b/converse",
            "",
            b"{}",
            "us-east-1",
            "bedrock",
            &fixture_creds(),
            fixture_time(),
        );
        assert_ne!(s1.authorization, s2.authorization);
    }

    #[test]
    fn uri_encode_path_percent_encodes_colon_preserves_slash() {
        // COR-15 / A-37: a Bedrock model id carries a ':' (…-v2:0); the
        // canonical URI must encode it to %3A while keeping the '/'
        // segment separators, or the signature won't match AWS's recompute.
        assert_eq!(
            uri_encode_path("/model/anthropic.claude-3-5-sonnet-20241022-v2:0/converse"),
            "/model/anthropic.claude-3-5-sonnet-20241022-v2%3A0/converse"
        );
        // Unreserved chars (`-._~`) + '/' pass through unchanged.
        assert_eq!(uri_encode_path("/model/test-a_b.c~d/converse"), "/model/test-a_b.c~d/converse");
        // Non-ASCII encodes per UTF-8 byte, uppercase hex (AWS get-utf8 vector).
        assert_eq!(uri_encode_path("/\u{1234}"), "/%E1%88%B4");
        // Other reserved chars also encode (space, '?', '#').
        assert_eq!(uri_encode_path("/a b?c#d"), "/a%20b%3Fc%23d");
    }

    #[test]
    fn signature_reflects_encoded_colon_path() {
        // Signing a ':'-bearing model path must be DETERMINISTIC (the
        // encoding is applied before hashing) and differ from a path that
        // genuinely has no colon — proving the colon is in the signed
        // canonical, not dropped.
        let colon = sign(
            "POST",
            "bedrock-runtime.us-east-1.amazonaws.com",
            "/model/anthropic.claude-v2:0/converse",
            "",
            b"{}",
            "us-east-1",
            "bedrock",
            &fixture_creds(),
            fixture_time(),
        );
        let colon2 = sign(
            "POST",
            "bedrock-runtime.us-east-1.amazonaws.com",
            "/model/anthropic.claude-v2:0/converse",
            "",
            b"{}",
            "us-east-1",
            "bedrock",
            &fixture_creds(),
            fixture_time(),
        );
        let no_colon = sign(
            "POST",
            "bedrock-runtime.us-east-1.amazonaws.com",
            "/model/anthropic.claude-v2X0/converse",
            "",
            b"{}",
            "us-east-1",
            "bedrock",
            &fixture_creds(),
            fixture_time(),
        );
        assert_eq!(colon.authorization, colon2.authorization, "must be deterministic");
        assert_ne!(
            colon.authorization, no_colon.authorization,
            "encoded ':' path must sign differently from a ':'-free path"
        );
    }

    #[test]
    fn signature_hex_is_64_chars() {
        let signed = sign(
            "POST",
            "bedrock-runtime.us-east-1.amazonaws.com",
            "/model/test/converse",
            "",
            b"{}",
            "us-east-1",
            "bedrock",
            &fixture_creds(),
            fixture_time(),
        );
        // The Signature= portion is hex-encoded SHA256 output → 64 chars.
        let signature_part = signed
            .authorization
            .split("Signature=")
            .nth(1)
            .expect("Signature= present");
        assert_eq!(signature_part.len(), 64, "got: {signature_part}");
        assert!(signature_part.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
