//! Percent-encoding helper (GOLD-ARCH-17, origin C-34/D-31).
//!
//! `email/gmail.rs` and `email/calendar.rs` each carried a byte-identical
//! RFC-3986 percent-encoder for OAuth/query strings. This is the single shared
//! implementation. Encodes everything outside the RFC-3986 *unreserved* set
//! (`A-Z a-z 0-9 - _ . ~`) as `%XX` (upper-case hex), which is the correct
//! escaping for query-string values and OAuth parameters. Avoids pulling in the
//! `url` crate for one helper.

/// Percent-encode `input` per RFC 3986: unreserved bytes pass through verbatim,
/// everything else becomes `%XX` (upper-case hex).
pub fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for b in input.bytes() {
        match b {
            // RFC 3986 unreserved set — safe verbatim.
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::url_encode;

    #[test]
    fn unreserved_pass_through_reserved_escaped() {
        assert_eq!(url_encode("abcXYZ09-_.~"), "abcXYZ09-_.~");
        assert_eq!(url_encode("a b/c=d&e"), "a%20b%2Fc%3Dd%26e");
        assert_eq!(url_encode(""), "");
        // Upper-case hex, multi-byte UTF-8 encoded byte-wise.
        assert_eq!(url_encode("ä"), "%C3%A4");
    }
}
