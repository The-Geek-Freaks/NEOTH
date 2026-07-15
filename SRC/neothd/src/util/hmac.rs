//! Domain-agnostic HMAC helpers shared by authenticated local protocols.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Compute HMAC-SHA256 for an arbitrary key and message.
pub fn sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc_4231_test_vector_1() {
        let got = sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            hex::encode(got),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }
}
