//! Secrets scanner — regex over text for common leaked-credential formats.
//!
//! Powers `neoth credential scan <path>`: walk a file/dir and flag lines that
//! look like a committed secret (AWS / GitHub / OpenAI / Slack / Google keys,
//! PEM private-key headers, and `api_key = "…"`-style assignments). Findings
//! **redact** the matched value (first/last 4 chars only) so the scan report
//! never re-leaks the secret it found.
//!
//! [`scan_text`] is pure (regex over an in-memory string) and unit-tested; the
//! CLI is the only thing that touches the filesystem.

use regex::Regex;

/// A named secret signature.
pub struct SecretPattern {
    pub name: &'static str,
    re: Regex,
}

/// Compile the curated pattern set. Built per call (a CLI scan is one-shot, so
/// no need for a static); every pattern is a valid literal (asserted by the
/// `patterns_all_compile` test).
pub fn patterns() -> Vec<SecretPattern> {
    let raw: &[(&'static str, &str)] = &[
        ("aws_access_key_id", r"AKIA[0-9A-Z]{16}"),
        ("github_token", r"gh[posru]_[A-Za-z0-9]{36,}"),
        ("openai_key", r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
        ("slack_token", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        ("google_api_key", r"AIza[0-9A-Za-z_-]{35}"),
        ("pem_private_key", r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
        (
            "generic_secret_assignment",
            r#"(?i)\b(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)\b\s*[:=]\s*['"]?[A-Za-z0-9_\-/+.]{12,}"#,
        ),
    ];
    raw.iter()
        .map(|(name, pat)| SecretPattern {
            name,
            re: Regex::new(pat).expect("secret-scan pattern is a valid literal regex"),
        })
        .collect()
}

/// One flagged occurrence. `redacted` is the masked secret — safe to print.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// 1-based line number.
    pub line: usize,
    /// Which pattern matched.
    pub pattern: &'static str,
    /// The matched text, masked to first/last 4 chars.
    pub redacted: String,
}

/// Mask a matched secret: short matches become all-`*`; longer ones show the
/// first + last 4 chars (enough to locate, not to use).
pub fn redact_match(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    if n <= 8 {
        return "*".repeat(n);
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[n - 4..].iter().collect();
    format!("{head}…{tail} ({n} chars)")
}

/// Scan in-memory text; return every match across every pattern, line by line.
pub fn scan_text(content: &str) -> Vec<Finding> {
    let pats = patterns();
    let mut out = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        for p in &pats {
            for m in p.re.find_iter(line) {
                out.push(Finding {
                    line: idx + 1,
                    pattern: p.name,
                    redacted: redact_match(m.as_str()),
                });
            }
        }
    }
    out
}

/// Default minimum token length for the entropy scan.
pub const ENTROPY_MIN_LEN: usize = 20;
/// Default minimum Shannon entropy (bits/char) for a token to be flagged. A
/// random base64/hex secret sits ~4.5-6.0; English words sit ~3.0-3.5.
pub const ENTROPY_MIN_BITS: f64 = 4.0;

/// Shannon entropy of `s` in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    let mut n = 0u32;
    for c in s.chars() {
        *counts.entry(c).or_insert(0u32) += 1;
        n += 1;
    }
    let nf = n as f64;
    -counts
        .values()
        .map(|&c| {
            let p = c as f64 / nf;
            p * p.log2()
        })
        .sum::<f64>()
}

/// Whether a token looks like a credential blob worth an entropy check:
/// credential charset only, long enough, and mixing letters + digits (so a
/// long lowercase word or a pure number isn't flagged).
fn is_entropy_candidate(tok: &str, min_len: usize) -> bool {
    if tok.chars().count() < min_len {
        return false;
    }
    let mut has_alpha = false;
    let mut has_digit = false;
    for c in tok.chars() {
        if c.is_ascii_alphabetic() {
            has_alpha = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        }
    }
    has_alpha && has_digit
}

/// Flag long, high-entropy tokens that no named pattern caught — catches
/// generic/opaque secrets (random API keys, hex/base64 blobs). Opt-in (the CLI
/// `--entropy` flag) because it trades precision for recall. Tokens are split
/// on any char outside the credential charset `[A-Za-z0-9+/=_-]`.
pub fn entropy_findings(content: &str, min_len: usize, min_bits: f64) -> Vec<Finding> {
    let mut out = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        for tok in line.split(|c: char| !(c.is_ascii_alphanumeric() || "+/=_-".contains(c))) {
            if !is_entropy_candidate(tok, min_len) {
                continue;
            }
            if shannon_entropy(tok) >= min_bits {
                out.push(Finding {
                    line: idx + 1,
                    pattern: "high_entropy",
                    redacted: redact_match(tok),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_all_compile() {
        // `patterns()` `.expect`s on each — this just proves the set builds.
        assert!(patterns().len() >= 7);
    }

    #[test]
    fn detects_common_secret_formats() {
        let text = "\
line one is clean
aws = AKIAIOSFODNN7EXAMPLE
gh = ghp_1234567890abcdefghijklmnopqrstuvwxyz12
oai = sk-proj-abcdefghijklmnopqrstuvwxyz0123456789
slack = xoxb-1234567890-abcdefABCDEF
google = AIzaSyA1234567890abcdefghijklmnopqrstuv
api_key = \"s3cr3t_value_here_long\"
";
        let f = scan_text(text);
        let names: Vec<&str> = f.iter().map(|x| x.pattern).collect();
        assert!(names.contains(&"aws_access_key_id"));
        assert!(names.contains(&"github_token"));
        assert!(names.contains(&"openai_key"));
        assert!(names.contains(&"slack_token"));
        assert!(names.contains(&"google_api_key"));
        assert!(names.contains(&"generic_secret_assignment"));
        // Line 1 (clean) produced no finding.
        assert!(f.iter().all(|x| x.line != 1));
    }

    #[test]
    fn finding_is_redacted_never_full_secret() {
        let f = scan_text("aws = AKIAIOSFODNN7EXAMPLE");
        let aws = f.iter().find(|x| x.pattern == "aws_access_key_id").unwrap();
        assert!(!aws.redacted.contains("AKIAIOSFODNN7EXAMPLE"), "must not echo the full secret");
        assert!(aws.redacted.starts_with("AKIA"));
        assert!(aws.redacted.contains("chars)"));
    }

    #[test]
    fn clean_text_yields_nothing() {
        assert!(scan_text("just some normal prose\nfn main() {}\n").is_empty());
    }

    #[test]
    fn line_numbers_are_one_based() {
        let f = scan_text("clean\nclean\nAKIAIOSFODNN7EXAMPLE");
        assert_eq!(f[0].line, 3);
    }

    #[test]
    fn redact_short_and_long() {
        assert_eq!(redact_match("short"), "*****");
        let long = redact_match("AKIAIOSFODNN7EXAMPLE");
        assert!(long.starts_with("AKIA") && long.ends_with("chars)"));
    }

    #[test]
    fn entropy_orders_random_above_words() {
        let random = shannon_entropy("a8Xk2Lp9Qz4Rw7Tm3Vb6Nc");
        let word = shannon_entropy("aaaaaaaaaaaaaaaaaaaa");
        let english = shannon_entropy("thequickbrownfoxjumps");
        assert!(random > english, "random > english prose");
        assert!(english > word, "varied > all-same-char");
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn entropy_flags_opaque_blob_skips_words_and_numbers() {
        let text = "\
greeting = hello world this is plain english prose only
token = a8Xk2Lp9Qz4Rw7Tm3Vb6Nc0Df1Gh5Jk
phone = 5551234567890123456789
";
        let f = entropy_findings(text, ENTROPY_MIN_LEN, ENTROPY_MIN_BITS);
        // The mixed-charset high-entropy token is flagged...
        assert!(f.iter().any(|x| x.line == 2 && x.pattern == "high_entropy"));
        // ...the prose line + the all-digit "phone" (no letters) are not.
        assert!(!f.iter().any(|x| x.line == 1));
        assert!(!f.iter().any(|x| x.line == 3), "pure-digit token has no letters → skipped");
    }

    #[test]
    fn entropy_finding_is_redacted() {
        let f = entropy_findings("k = a8Xk2Lp9Qz4Rw7Tm3Vb6Nc0Df1Gh5Jk", ENTROPY_MIN_LEN, ENTROPY_MIN_BITS);
        assert_eq!(f.len(), 1);
        assert!(f[0].redacted.contains("chars)"));
        assert!(!f[0].redacted.contains("a8Xk2Lp9Qz4Rw7Tm3Vb6Nc0Df1Gh5Jk"));
    }
}
