//! GOLD-ADOPT-16 — base64 deeplink share.
//!
//! `neoth recipe share <file>` encodes a recipe's YAML into a portable
//! `neoth://recipe/<base64url>` link the operator can paste anywhere; `neoth
//! recipe run <link>` decodes it back to YAML and runs it. URL-safe, unpadded
//! base64 so the link survives copy/paste + URL contexts without escaping.

use base64::Engine;

use super::schema::{RecipeError, RecipeSpec};

/// Deeplink scheme prefix.
pub const SCHEME: &str = "neoth://recipe/";

/// Encode recipe YAML into a `neoth://recipe/<base64url>` deeplink. The input is
/// re-serialised from a PARSED spec so a share link is always a valid recipe
/// (never ships a malformed file).
pub fn encode(spec: &RecipeSpec) -> Result<String, RecipeError> {
    let yaml = serde_yaml::to_string(spec).map_err(|e| RecipeError::Parse(e.to_string()))?;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(yaml.as_bytes());
    Ok(format!("{SCHEME}{b64}"))
}

/// Decode a `neoth://recipe/<b64>` deeplink (or a bare base64 payload) back to a
/// parsed, structurally-validated [`RecipeSpec`].
pub fn decode(link: &str) -> Result<RecipeSpec, RecipeError> {
    let payload = link.strip_prefix(SCHEME).unwrap_or(link).trim();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .map_err(|e| RecipeError::Parse(format!("invalid deeplink base64: {e}")))?;
    let yaml =
        String::from_utf8(bytes).map_err(|e| RecipeError::Parse(format!("deeplink not utf-8: {e}")))?;
    RecipeSpec::parse(&yaml)
}

/// Is this string a recipe deeplink (vs a file path)?
pub fn is_deeplink(s: &str) -> bool {
    s.starts_with(SCHEME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_a_deeplink() {
        let spec = RecipeSpec::parse(
            "name: scan\ndescription: port scan\nprompt: \"Scan {{host}}\"\nparameters:\n  - key: host\n",
        )
        .unwrap();
        let link = encode(&spec).unwrap();
        assert!(link.starts_with(SCHEME));
        assert!(is_deeplink(&link));
        let back = decode(&link).unwrap();
        assert_eq!(back.name, "scan");
        assert_eq!(back.parameters[0].key, "host");
        assert_eq!(back, spec);
    }

    #[test]
    fn decodes_a_bare_payload_without_scheme() {
        let spec = RecipeSpec::parse("name: g\nprompt: \"hi\"\n").unwrap();
        let link = encode(&spec).unwrap();
        let bare = link.strip_prefix(SCHEME).unwrap();
        assert_eq!(decode(bare).unwrap().name, "g");
    }

    #[test]
    fn rejects_garbage_deeplink() {
        assert!(decode("neoth://recipe/!!!not-base64!!!").is_err());
        // Valid base64 of non-recipe text → parse error downstream.
        let junk = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"just a string");
        assert!(decode(&junk).is_err());
    }

    #[test]
    fn is_deeplink_distinguishes_paths() {
        assert!(is_deeplink("neoth://recipe/abc"));
        assert!(!is_deeplink("./recipes/scan.yaml"));
        assert!(!is_deeplink("/home/x/r.yaml"));
    }
}
