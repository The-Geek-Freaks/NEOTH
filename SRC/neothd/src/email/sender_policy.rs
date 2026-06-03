//! EM-01b P1a — trusted-sender policy: domain allowlist + SPF/DKIM/DMARC
//! visibility.
//!
//! This slice is deliberately VISIBILITY-ONLY. It annotates a triage result
//! with two signals — whether the sender's domain is on the operator's
//! `email.trusted_domains` allowlist, and the SPF/DKIM/DMARC verdicts the
//! receiving server reported — and surfaces them in the `neoth email fetch`
//! output + the `EMAIL_INGRESS_TRIAGED` audit frame.
//!
//! THE INVARIANT ("trusted but still sanitized"): [`annotate_sender_policy`]
//! runs AFTER [`super::inbound::triage_inbound`] and touches ONLY the two new
//! visibility fields — it never changes `action`, `clean_body`, or `threat`.
//! So a trusted sender's mail is still fully sanitized + threat-scored; trust
//! can never weaken a security decision. Enforcement (auto-deliver a
//! trusted+DMARC-pass sender, etc.) is a deliberate later slice, gated.

use super::inbound::{AuthVerdict, EmailAuthStatus, InboundEmail, InboundTriage};

/// Parse a receiving server's `Authentication-Results` header into per-mechanism
/// verdicts. Robust to ordering, casing, and the comment/`smtp.mailfrom=`
/// clutter real headers carry; a missing or unparseable mechanism is
/// [`AuthVerdict::Unknown`].
///
/// Example header (Gmail):
/// `mx.google.com; spf=pass (google.com: ...) smtp.mailfrom=acme.com;
///  dkim=pass header.i=@acme.com; dmarc=pass (p=REJECT ...) header.from=acme.com`
pub fn parse_authentication_results(header: &str) -> EmailAuthStatus {
    EmailAuthStatus {
        spf: extract_verdict(header, "spf"),
        dkim: extract_verdict(header, "dkim"),
        dmarc: extract_verdict(header, "dmarc"),
    }
}

/// Pull the verdict word for one mechanism (`spf` / `dkim` / `dmarc`). Only
/// matches the mechanism as a TOKEN start (preceded by start-of-string,
/// whitespace, or `;`) so `dkim=` never matches inside another token.
fn extract_verdict(header: &str, mechanism: &str) -> AuthVerdict {
    let lower = header.to_ascii_lowercase();
    let needle = format!("{mechanism}=");
    let bytes = lower.as_bytes();
    for (i, _) in lower.match_indices(&needle) {
        let preceded_ok =
            i == 0 || matches!(bytes[i - 1], b' ' | b';' | b'\t' | b'\n' | b'\r' | b',');
        if !preceded_ok {
            continue;
        }
        let after = &lower[i + needle.len()..];
        let word: String = after.chars().take_while(|c| c.is_ascii_alphabetic()).collect();
        return verdict_from_word(&word);
    }
    AuthVerdict::Unknown
}

fn verdict_from_word(word: &str) -> AuthVerdict {
    match word {
        "pass" => AuthVerdict::Pass,
        "fail" => AuthVerdict::Fail,
        "softfail" => AuthVerdict::SoftFail,
        "neutral" => AuthVerdict::Neutral,
        "none" => AuthVerdict::NoneResult,
        _ => AuthVerdict::Unknown,
    }
}

/// `true` if `from_domain` matches a trusted domain EXACTLY or is a SUBDOMAIN
/// of one. The subdomain check requires a leading dot (`mail.acme.com` matches
/// `acme.com`, but `notacme.com` / `evil-acme.com` do NOT — a suffix-injection
/// guard). Case-insensitive; empty/`None` inputs are untrusted.
pub fn domain_is_trusted(from_domain: Option<&str>, trusted_domains: &[String]) -> bool {
    let Some(domain) = from_domain else {
        return false;
    };
    let domain = domain.trim().to_ascii_lowercase();
    if domain.is_empty() {
        return false;
    }
    trusted_domains.iter().any(|t| {
        let t = t.trim().trim_start_matches('.').to_ascii_lowercase();
        !t.is_empty() && (domain == t || domain.ends_with(&format!(".{t}")))
    })
}

/// Annotate a triage result with the P1a visibility signals — and ONLY those.
/// Never touches `action`/`clean_body`/`threat` ("trusted but still sanitized").
pub fn annotate_sender_policy(
    mut triage: InboundTriage,
    email: &InboundEmail,
    trusted_domains: &[String],
) -> InboundTriage {
    triage.sender_trusted = domain_is_trusted(email.from_domain.as_deref(), trusted_domains);
    triage.auth = email
        .auth_results
        .as_deref()
        .map(parse_authentication_results);
    triage
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::email::inbound::{InboundAction, extract_from_domain, triage_inbound};

    fn email_with(from: &str, auth: Option<&str>) -> InboundEmail {
        InboundEmail {
            uid: "u".into(),
            from: from.into(),
            from_domain: extract_from_domain(from),
            subject: "s".into(),
            body: "Quarterly report attached, thanks.".into(),
            attachment_filenames: vec![],
            message_id: None,
            auth_results: auth.map(|s| s.to_string()),
        }
    }

    #[test]
    fn parse_gmail_all_pass() {
        let h = "mx.google.com; spf=pass (google.com: domain of a@acme.com) smtp.mailfrom=acme.com; \
                 dkim=pass header.i=@acme.com; dmarc=pass (p=REJECT) header.from=acme.com";
        let r = parse_authentication_results(h);
        assert_eq!(r.spf, AuthVerdict::Pass);
        assert_eq!(r.dkim, AuthVerdict::Pass);
        assert_eq!(r.dmarc, AuthVerdict::Pass);
    }

    #[test]
    fn parse_mixed_and_softfail() {
        let h = "mx; spf=softfail; dkim=fail header.i=@x; dmarc=none";
        let r = parse_authentication_results(h);
        assert_eq!(r.spf, AuthVerdict::SoftFail);
        assert_eq!(r.dkim, AuthVerdict::Fail);
        assert_eq!(r.dmarc, AuthVerdict::NoneResult);
    }

    #[test]
    fn parse_missing_mechanism_is_unknown() {
        let r = parse_authentication_results("mx; spf=pass");
        assert_eq!(r.spf, AuthVerdict::Pass);
        assert_eq!(r.dkim, AuthVerdict::Unknown);
        assert_eq!(r.dmarc, AuthVerdict::Unknown);
        // Empty header → all unknown.
        let e = parse_authentication_results("");
        assert_eq!(e.spf, AuthVerdict::Unknown);
    }

    #[test]
    fn extract_does_not_match_substring_token() {
        // A header where "dkim" appears only inside an unrelated token must not
        // be mis-read; the real dkim verdict is fail.
        let r = parse_authentication_results("mx; xdkim=pass; dkim=fail");
        assert_eq!(r.dkim, AuthVerdict::Fail);
    }

    #[test]
    fn trusted_exact_and_subdomain() {
        let allow = vec!["acme.com".to_string(), ".bank.example".to_string()];
        assert!(domain_is_trusted(Some("acme.com"), &allow));
        assert!(domain_is_trusted(Some("mail.acme.com"), &allow));
        assert!(domain_is_trusted(Some("ACME.COM"), &allow)); // case-insensitive
        assert!(domain_is_trusted(Some("secure.bank.example"), &allow));
    }

    #[test]
    fn untrusted_suffix_injection_and_empty() {
        let allow = vec!["acme.com".to_string()];
        // Suffix-injection: must NOT match.
        assert!(!domain_is_trusted(Some("notacme.com"), &allow));
        assert!(!domain_is_trusted(Some("evil-acme.com"), &allow));
        assert!(!domain_is_trusted(Some("acme.com.attacker.tk"), &allow));
        assert!(!domain_is_trusted(Some("other.org"), &allow));
        assert!(!domain_is_trusted(None, &allow));
        // Empty allowlist trusts nothing.
        assert!(!domain_is_trusted(Some("acme.com"), &[]));
    }

    #[test]
    fn annotate_sets_visibility_without_changing_decision() {
        // A phishing email from a "trusted" domain must STAY quarantined —
        // trust is visibility only, never a band override.
        let e = email_with(
            "Security <noreply@acme.com>",
            Some("mx; spf=pass; dkim=pass; dmarc=pass"),
        );
        // Force a quarantine verdict via the body.
        let mut phish = e.clone();
        phish.body =
            "Your account has been suspended. Verify your account and confirm your identity.".into();
        let triage = triage_inbound(&phish);
        assert_eq!(triage.action, InboundAction::Quarantine);
        let annotated = annotate_sender_policy(triage, &phish, &["acme.com".to_string()]);
        // Trust + auth surfaced...
        assert!(annotated.sender_trusted);
        assert_eq!(annotated.auth.unwrap().dmarc, AuthVerdict::Pass);
        // ...but the security decision is UNCHANGED.
        assert_eq!(annotated.action, InboundAction::Quarantine);
        assert!(annotated.clean_body.is_empty());
    }

    #[test]
    fn annotate_untrusted_no_auth() {
        let e = email_with("a@stranger.example.org", None);
        let triage = triage_inbound(&e);
        let annotated = annotate_sender_policy(triage, &e, &["acme.com".to_string()]);
        assert!(!annotated.sender_trusted);
        assert!(annotated.auth.is_none());
    }
}
