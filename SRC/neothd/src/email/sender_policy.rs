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
//! can never weaken a security decision.
//!
//! ## The gated ENFORCEMENT slice ([`apply_trust_policy`])
//!
//! [`apply_trust_policy`] is the deliberate later slice — opt-in via
//! `email.trusted_sender_policy` (default off). It combines the allowlist match
//! with the SPF/DKIM/DMARC verdicts to make TWO bounded decisions:
//!
//! - **Spoof defence (the security win, always-on when the policy is on):** a
//!   domain allowlist ALONE is spoofable — anyone can put `From: ceo@acme.com`
//!   in a header. When a "trusted" domain's mail carries a FAILING SPF/DKIM/
//!   DMARC verdict, the receiving server has already told us the alignment was
//!   rejected → that's the spoof tell. The policy ESCALATES it to quarantine
//!   (only ever more restrictive). This is why visibility alone is not enough:
//!   without it, the allowlist is a liability (an attacker spoofs a trusted
//!   domain to look safer).
//! - **Relaxation (double-gated, conservative):** only under the additional
//!   `trusted_sender_allow_relax` flag, a VERIFIED-trust sender (allowlist +
//!   auth pass) whose mail is a borderline `ReviewQueue` — AND that no LLM
//!   tie-break already ruled on — is delivered. It NEVER downgrades a
//!   quarantine + never un-sanitizes; the sanitizer/scorer always ran first.

use super::inbound::{
    AuthVerdict, EmailAuthStatus, InboundAction, InboundEmail, InboundTriage, TrustPolicyOutcome,
};

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

/// The trust-policy decision after combining the allowlist match with the
/// authentication (SPF/DKIM/DMARC) verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDecision {
    /// Sender is not on the allowlist — the policy has nothing to say.
    NotTrusted,
    /// Trusted domain, but the receiving server reported NO auth results —
    /// the allowlist match cannot be confirmed not-spoofed. No relaxation.
    TrustedUnverified,
    /// Trusted domain AND authentication confirms alignment (DMARC pass, or
    /// DKIM+SPF both pass). Eligible for the gated relaxation.
    VerifiedTrust,
    /// Trusted domain but a mechanism explicitly FAILED — the spoof tell.
    SpoofSuspected,
}

/// Combine the allowlist flag + the parsed auth into a [`TrustDecision`]. PURE.
///
/// An explicit `Fail` on ANY of DMARC/DKIM/SPF for a trusted-domain claim is
/// treated as a spoof: the receiving server rejected the alignment, so the
/// `From` domain is almost certainly forged. `SoftFail`/`Neutral`/`None`/
/// `Unknown` are NOT treated as spoofs (too weak a signal to escalate on) but
/// also do NOT qualify as verified (no relaxation) — the conservative middle.
pub fn evaluate_trust_decision(
    sender_trusted: bool,
    auth: Option<&EmailAuthStatus>,
) -> TrustDecision {
    if !sender_trusted {
        return TrustDecision::NotTrusted;
    }
    let Some(a) = auth else {
        return TrustDecision::TrustedUnverified;
    };
    if a.dmarc == AuthVerdict::Fail || a.dkim == AuthVerdict::Fail || a.spf == AuthVerdict::Fail {
        return TrustDecision::SpoofSuspected;
    }
    // DMARC pass is the strongest single signal (it checks From-alignment);
    // otherwise require BOTH DKIM and SPF to pass.
    if a.dmarc == AuthVerdict::Pass
        || (a.dkim == AuthVerdict::Pass && a.spf == AuthVerdict::Pass)
    {
        return TrustDecision::VerifiedTrust;
    }
    TrustDecision::TrustedUnverified
}

/// Apply the GATED trusted-sender policy to an already-annotated triage.
///
/// Returns `None` when the policy is disabled (`enabled == false`). Otherwise
/// returns `Some(outcome)` AND records it on `triage.trust_policy`. Conservative
/// by construction:
/// - **Spoof** → escalate `Deliver`/`ReviewQueue` to `Quarantine` + blank the
///   body. Never touches an already-`Quarantine`/`DroppedAtSanitizer` verdict.
/// - **Relax** (only with `allow_relax`) → a `VerifiedTrust` borderline
///   `ReviewQueue` with NO prior LLM tie-break becomes `Deliver`. NEVER
///   downgrades a quarantine; if a tie-break already ruled, its verdict stands.
pub fn apply_trust_policy(
    triage: &mut InboundTriage,
    enabled: bool,
    allow_relax: bool,
) -> Option<TrustPolicyOutcome> {
    if !enabled {
        return None;
    }
    let decision = evaluate_trust_decision(triage.sender_trusted, triage.auth.as_ref());
    let outcome = match decision {
        TrustDecision::SpoofSuspected
            if matches!(
                triage.action,
                InboundAction::Deliver | InboundAction::ReviewQueue
            ) =>
        {
            triage.action = InboundAction::Quarantine;
            triage.clean_body = String::new();
            TrustPolicyOutcome::EscalatedSpoof
        }
        TrustDecision::VerifiedTrust
            if allow_relax
                && matches!(triage.action, InboundAction::ReviewQueue)
                && triage.tiebreak.is_none() =>
        {
            triage.action = InboundAction::Deliver;
            TrustPolicyOutcome::RelaxedToDeliver
        }
        _ => TrustPolicyOutcome::NoChange,
    };
    triage.trust_policy = Some(outcome);
    Some(outcome)
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

    // ── gated enforcement (apply_trust_policy) ──────────────────────────────

    fn status(spf: AuthVerdict, dkim: AuthVerdict, dmarc: AuthVerdict) -> EmailAuthStatus {
        EmailAuthStatus { spf, dkim, dmarc }
    }

    #[test]
    fn decision_matrix() {
        use AuthVerdict::*;
        use TrustDecision::*;
        // Untrusted → nothing, regardless of auth.
        assert_eq!(
            evaluate_trust_decision(false, Some(&status(Pass, Pass, Pass))),
            NotTrusted
        );
        // Trusted + no auth → unverified.
        assert_eq!(evaluate_trust_decision(true, None), TrustedUnverified);
        // Trusted + DMARC fail → spoof (the key case).
        assert_eq!(
            evaluate_trust_decision(true, Some(&status(Pass, Pass, Fail))),
            SpoofSuspected
        );
        // Trusted + DKIM fail → spoof.
        assert_eq!(
            evaluate_trust_decision(true, Some(&status(Pass, Fail, NoneResult))),
            SpoofSuspected
        );
        // Trusted + DMARC pass → verified.
        assert_eq!(
            evaluate_trust_decision(true, Some(&status(NoneResult, NoneResult, Pass))),
            VerifiedTrust
        );
        // Trusted + DKIM+SPF pass (no DMARC) → verified.
        assert_eq!(
            evaluate_trust_decision(true, Some(&status(Pass, Pass, Unknown))),
            VerifiedTrust
        );
        // Trusted + softfail only → unverified (too weak to escalate or relax).
        assert_eq!(
            evaluate_trust_decision(true, Some(&status(SoftFail, Unknown, Unknown))),
            TrustedUnverified
        );
    }

    /// Helper: triage a benign mail, annotate as trusted, with the given auth.
    fn trusted_triage(auth: Option<&str>) -> InboundTriage {
        let e = email_with("Boss <ceo@acme.com>", auth);
        let t = triage_inbound(&e);
        annotate_sender_policy(t, &e, &["acme.com".to_string()])
    }

    #[test]
    fn policy_disabled_is_inactive() {
        let mut t = trusted_triage(Some("mx; spf=fail; dkim=fail; dmarc=fail"));
        let before = t.action;
        assert_eq!(apply_trust_policy(&mut t, false, false), None);
        assert_eq!(t.action, before, "disabled policy changes nothing");
        assert!(t.trust_policy.is_none());
    }

    #[test]
    fn spoof_escalates_a_deliverable_to_quarantine() {
        // A trusted-domain From with FAILING auth = spoof → quarantine even
        // though the body itself scored Deliver.
        let mut t = trusted_triage(Some("mx; spf=fail; dkim=fail; dmarc=fail"));
        assert_eq!(t.action, InboundAction::Deliver, "benign body scores Deliver");
        let out = apply_trust_policy(&mut t, true, false);
        assert_eq!(out, Some(TrustPolicyOutcome::EscalatedSpoof));
        assert_eq!(t.action, InboundAction::Quarantine);
        assert!(t.clean_body.is_empty(), "spoof body must not reach the LLM");
        assert_eq!(t.trust_policy, Some(TrustPolicyOutcome::EscalatedSpoof));
    }

    #[test]
    fn verified_trust_does_not_relax_without_the_flag() {
        // A verified-trust borderline is NOT relaxed unless allow_relax is on.
        let mut t = trusted_triage(Some("mx; spf=pass; dkim=pass; dmarc=pass"));
        t.action = InboundAction::ReviewQueue; // force a borderline
        let out = apply_trust_policy(&mut t, true, false);
        assert_eq!(out, Some(TrustPolicyOutcome::NoChange));
        assert_eq!(t.action, InboundAction::ReviewQueue, "no relax without the flag");
    }

    #[test]
    fn verified_trust_relaxes_a_borderline_with_the_flag() {
        let mut t = trusted_triage(Some("mx; spf=pass; dkim=pass; dmarc=pass"));
        t.action = InboundAction::ReviewQueue;
        let out = apply_trust_policy(&mut t, true, true);
        assert_eq!(out, Some(TrustPolicyOutcome::RelaxedToDeliver));
        assert_eq!(t.action, InboundAction::Deliver);
    }

    #[test]
    fn relax_never_overrides_an_llm_tiebreak() {
        // If the LLM tie-break already ruled, trust must NOT relax over it.
        let mut t = trusted_triage(Some("mx; spf=pass; dkim=pass; dmarc=pass"));
        t.action = InboundAction::ReviewQueue;
        t.tiebreak = Some(crate::email::inbound::TiebreakVerdict::Phishing);
        let out = apply_trust_policy(&mut t, true, true);
        assert_eq!(out, Some(TrustPolicyOutcome::NoChange));
        assert_eq!(t.action, InboundAction::ReviewQueue, "tie-break verdict stands");
    }

    #[test]
    fn relax_never_downgrades_a_quarantine() {
        // A real threat from a verified-trust sender STAYS quarantined.
        let mut e = email_with("ceo@acme.com", Some("mx; spf=pass; dkim=pass; dmarc=pass"));
        e.body =
            "Your account has been suspended. Verify your account and confirm your identity.".into();
        let t = triage_inbound(&e);
        let mut t = annotate_sender_policy(t, &e, &["acme.com".to_string()]);
        assert_eq!(t.action, InboundAction::Quarantine);
        let out = apply_trust_policy(&mut t, true, true);
        assert_eq!(out, Some(TrustPolicyOutcome::NoChange));
        assert_eq!(t.action, InboundAction::Quarantine, "trust never frees a real threat");
    }
}
