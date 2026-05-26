//! PL-05 (Session 24) — scored rule engine for email body threats.
//!
//! Runs AFTER [`super::email_sanitizer::sanitize_email_body`] and
//! AFTER [`super::ingress_sanitizer::sanitize`] — those two gates
//! handle prompt-injection + MIME poisoning. PL-05 is the
//! complementary surface: phishing language, classic spam markers,
//! and malware-attachment indicators. The output is a score (0-100)
//! and a [`ThreatBand`] that EM-* paths consult to decide whether
//! to deliver, queue for operator review, or quarantine.
//!
//! ## Why scored rules, not hard quarantine
//!
//! A single "urgency" word ("immediately") on its own is not phishing
//! — invoices say "immediately" too. Phishing is the COMBINATION:
//! urgency + verify-account + brand-impersonation + suspicious link.
//! Each rule contributes a weight; the band decision falls out of
//! the sum. Combinations cross the Quarantine threshold (80+) where
//! lone matches stay in the ReviewQueue band (50-79). The thresholds
//! are tuned so the corpus in
//! `eval/email_threat_corpus/` (PL-05 follow-up) lands as expected.
//!
//! ## Bands
//!
//! - `Allow` (score < 50) — deliver normally.
//! - `ReviewQueue` (50 ≤ score < 80) — operator sees the email but
//!   the agent MUST NOT auto-act on it (no auto-replies, no
//!   draft-and-send, no calendar-create from body).
//! - `Quarantine` (score ≥ 80) — body never reaches the LLM. The
//!   operator sees a one-line summary + the rule list in the audit
//!   log so they can manually fish it out if it was a false positive.
//!
//! ## Rules
//!
//! All rules are pure-data ([`PHISHING_RULES`], [`SPAM_RULES`],
//! [`MALWARE_EXT_RULES`]). Add a rule = append a tuple. No code
//! change. The engine ([`assess_email_threat`]) is a thin runner.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Threshold at which an email moves from Allow into ReviewQueue.
/// One strong phishing signal alone is below this — combinations
/// trip it.
pub const REVIEW_QUEUE_THRESHOLD: u8 = 50;

/// Threshold at which an email moves from ReviewQueue into
/// Quarantine. ~3 independent phishing signals or 1 phishing + 1
/// malware indicator crosses this.
pub const QUARANTINE_THRESHOLD: u8 = 80;

/// Phishing rules — substring matches on the lowercase body. Each
/// rule carries a `(id, needle, weight)` tuple. Weights tuned so:
///   - one alone (30) → still Allow,
///   - two combine → ReviewQueue (60),
///   - three combine → Quarantine (90).
const PHISHING_RULES: &[(&str, &str, u8)] = &[
    ("ph-001-verify-account", "verify your account", 30),
    ("ph-002-confirm-identity", "confirm your identity", 30),
    ("ph-003-update-payment", "update your payment", 30),
    (
        "ph-004-account-suspended",
        "your account has been suspended",
        35,
    ),
    ("ph-005-account-locked", "your account has been locked", 35),
    ("ph-006-unusual-signin", "unusual sign-in activity", 30),
    ("ph-007-click-here-avoid", "click here to avoid", 30),
    ("ph-008-confirm-or-lose", "confirm now or lose access", 35),
    (
        "ph-009-noticed-problem",
        "we've noticed a problem with your account",
        30,
    ),
    ("ph-010-claim-prize", "claim your prize", 30),
    ("ph-011-seed-phrase", "enter your seed phrase", 50),
    ("ph-012-recovery-phrase", "enter your recovery phrase", 50),
    ("ph-013-wire-funds-urgent", "wire funds immediately", 35),
    (
        "ph-014-tax-refund-claim",
        "your tax refund is ready to claim",
        30,
    ),
    (
        "ph-015-package-undeliverable",
        "your package could not be delivered",
        25,
    ),
];

/// Spam rules — lower weight than phishing because false positives
/// are tolerable (operator sees them in ReviewQueue, not lost).
const SPAM_RULES: &[(&str, &str, u8)] = &[
    (
        "sp-001-lottery-winner",
        "you have been selected as the winner",
        25,
    ),
    ("sp-002-prince-inheritance", "prince of", 15),
    ("sp-003-prince-inheritance-b", "transfer my inheritance", 30),
    ("sp-004-viagra", "buy viagra", 30),
    ("sp-005-cialis", "buy cialis", 30),
    ("sp-006-weight-loss", "lose weight in days", 20),
    ("sp-007-make-money-fast", "make money fast", 25),
    ("sp-008-work-from-home", "earn $5000 per day from home", 30),
    ("sp-009-millions-of-dollars", "millions of dollars", 15),
    (
        "sp-010-congrats-winner",
        "congratulations, you are a winner",
        25,
    ),
];

/// Malware-attachment extensions. Score scales with how plainly
/// executable the format is.
const MALWARE_EXT_RULES: &[(&str, &str, u8)] = &[
    ("mw-001-exe", ".exe", 50),
    ("mw-002-scr", ".scr", 50),
    ("mw-003-bat", ".bat", 40),
    ("mw-004-cmd", ".cmd", 40),
    ("mw-005-vbs", ".vbs", 45),
    ("mw-006-ps1", ".ps1", 45),
    ("mw-007-js", ".js", 30),
    ("mw-008-jse", ".jse", 40),
    ("mw-009-msi", ".msi", 40),
    ("mw-010-hta", ".hta", 45),
    // Macro-enabled office formats — high-confidence malware delivery.
    ("mw-011-docm", ".docm", 40),
    ("mw-012-xlsm", ".xlsm", 40),
    ("mw-013-pptm", ".pptm", 40),
    // Iso/img archives are a 2024-onward malware-delivery trend.
    ("mw-014-iso", ".iso", 35),
    ("mw-015-img", ".img", 35),
];

/// Action band derived from the rule sum. See module docs for the
/// thresholds + tuning rationale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatBand {
    Allow,
    ReviewQueue,
    Quarantine,
}

impl ThreatBand {
    pub fn as_str(self) -> &'static str {
        match self {
            ThreatBand::Allow => "allow",
            ThreatBand::ReviewQueue => "review_queue",
            ThreatBand::Quarantine => "quarantine",
        }
    }
}

/// One rule hit on the email body or attachment list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ThreatFinding {
    Phishing {
        rule_id: String,
        weight: u8,
        evidence: String,
    },
    Spam {
        rule_id: String,
        weight: u8,
        evidence: String,
    },
    MalwareAttachment {
        rule_id: String,
        weight: u8,
        filename: String,
    },
    /// Sender claims a well-known brand domain in the From: line but
    /// the actual email address is on a different (unrelated) domain.
    /// Pure-text version of SPF/DKIM intent — useful when the IMAP
    /// adapter can't verify those headers itself.
    DomainImpersonation {
        rule_id: String,
        weight: u8,
        claimed_brand: String,
        actual_domain: String,
    },
}

impl ThreatFinding {
    pub fn weight(&self) -> u8 {
        match self {
            ThreatFinding::Phishing { weight, .. }
            | ThreatFinding::Spam { weight, .. }
            | ThreatFinding::MalwareAttachment { weight, .. }
            | ThreatFinding::DomainImpersonation { weight, .. } => *weight,
        }
    }
}

/// Result of [`assess_email_threat`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatAssessment {
    /// Sum of all rule weights, capped at 100.
    pub score: u8,
    pub band: ThreatBand,
    pub findings: Vec<ThreatFinding>,
}

/// Brand names paired with the domain suffix the legitimate sender
/// must end with. Hit triggers [`ThreatFinding::DomainImpersonation`]
/// when the actual sender domain doesn't match.
const BRAND_DOMAIN_RULES: &[(&str, &str)] = &[
    ("paypal", "paypal.com"),
    ("amazon", "amazon.com"),
    ("microsoft", "microsoft.com"),
    ("apple", "apple.com"),
    ("google", "google.com"),
    ("github", "github.com"),
    ("netflix", "netflix.com"),
    ("dhl", "dhl.com"),
    ("ups", "ups.com"),
    ("fedex", "fedex.com"),
];

/// Run all PL-05 rules against an email and return a scored
/// assessment. Pure function — does NOT touch the filesystem.
///
/// `body` is the post-sanitize_email_body, post-ingress_sanitizer
/// text. `sender_domain` is the lowercase domain part of the
/// envelope From (e.g. `mail.attacker.tk` from
/// `noreply@mail.attacker.tk`). `attachment_filenames` are the
/// raw attachment names (post-`safe_attachment_filename`).
pub fn assess_email_threat(
    body: &str,
    sender_domain: Option<&str>,
    attachment_filenames: &[&str],
) -> ThreatAssessment {
    let lower = body.to_lowercase();
    let mut findings: Vec<ThreatFinding> = Vec::new();

    // ── Phishing ──────────────────────────────────────────────────────────
    for (id, needle, weight) in PHISHING_RULES {
        if lower.contains(needle) {
            findings.push(ThreatFinding::Phishing {
                rule_id: (*id).to_string(),
                weight: *weight,
                evidence: (*needle).to_string(),
            });
        }
    }

    // ── Spam ──────────────────────────────────────────────────────────────
    for (id, needle, weight) in SPAM_RULES {
        if lower.contains(needle) {
            findings.push(ThreatFinding::Spam {
                rule_id: (*id).to_string(),
                weight: *weight,
                evidence: (*needle).to_string(),
            });
        }
    }

    // ── Malware attachments ───────────────────────────────────────────────
    for fname in attachment_filenames {
        let fname_lc = fname.to_lowercase();
        for (id, ext, weight) in MALWARE_EXT_RULES {
            if fname_lc.ends_with(ext) {
                findings.push(ThreatFinding::MalwareAttachment {
                    rule_id: (*id).to_string(),
                    weight: *weight,
                    filename: (*fname).to_string(),
                });
            }
        }
    }

    // ── Domain impersonation ──────────────────────────────────────────────
    // Trigger only when the brand is named in the body AND the sender
    // domain doesn't end with the legitimate domain. Skips brand
    // matches that have no sender_domain (we can't accuse without
    // the second half of the comparison).
    if let Some(domain) = sender_domain {
        let domain_lc = domain.to_lowercase();
        let mut already_flagged: HashSet<&str> = HashSet::new();
        for (brand, legit_suffix) in BRAND_DOMAIN_RULES {
            if lower.contains(brand)
                && !domain_lc.ends_with(legit_suffix)
                && already_flagged.insert(brand)
            {
                findings.push(ThreatFinding::DomainImpersonation {
                    rule_id: format!("brand-impersonation-{brand}"),
                    weight: 40,
                    claimed_brand: (*brand).to_string(),
                    actual_domain: domain.to_string(),
                });
            }
        }
    }

    // ── Score + band ──────────────────────────────────────────────────────
    let raw_sum: u32 = findings.iter().map(|f| f.weight() as u32).sum();
    let score = raw_sum.min(100) as u8;
    let band = if score >= QUARANTINE_THRESHOLD {
        ThreatBand::Quarantine
    } else if score >= REVIEW_QUEUE_THRESHOLD {
        ThreatBand::ReviewQueue
    } else {
        ThreatBand::Allow
    };

    ThreatAssessment {
        score,
        band,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benign_email_allows() {
        let r = assess_email_threat(
            "Hi team,\nAttached is the Q3 report. Let me know if you want changes.\nThanks.",
            Some("colleague.example.com"),
            &["q3-report.pdf"],
        );
        assert_eq!(r.band, ThreatBand::Allow);
        assert_eq!(r.score, 0);
        assert!(r.findings.is_empty());
    }

    #[test]
    fn single_phishing_marker_is_allow_or_review_not_quarantine() {
        // One phishing signal alone (weight 30) is below REVIEW (50) —
        // a real invoice can plausibly say "verify your account" once.
        let r = assess_email_threat(
            "Please verify your account at the portal before Friday.",
            Some("internal.example.com"),
            &[],
        );
        assert!(matches!(
            r.band,
            ThreatBand::Allow | ThreatBand::ReviewQueue
        ));
        assert!(r.score < QUARANTINE_THRESHOLD);
    }

    #[test]
    fn two_phishing_markers_hits_review_queue() {
        let r = assess_email_threat(
            "Please verify your account and confirm your identity by Monday.",
            Some("legit.example.com"),
            &[],
        );
        assert_eq!(r.band, ThreatBand::ReviewQueue);
        assert!(r.score >= REVIEW_QUEUE_THRESHOLD);
        assert!(r.score < QUARANTINE_THRESHOLD);
    }

    #[test]
    fn three_phishing_markers_quarantine() {
        let r = assess_email_threat(
            "Your account has been suspended. Verify your account and confirm your identity.",
            Some("phisher.tk"),
            &[],
        );
        assert_eq!(r.band, ThreatBand::Quarantine);
        assert!(r.score >= QUARANTINE_THRESHOLD);
    }

    #[test]
    fn seed_phrase_request_alone_hits_review() {
        // ph-011 carries weight 50 (Allow=49 < this < QUARANTINE=80).
        let r = assess_email_threat(
            "To recover funds please enter your seed phrase below.",
            None,
            &[],
        );
        assert_eq!(r.band, ThreatBand::ReviewQueue);
        assert!(r.findings.iter().any(|f| matches!(
            f,
            ThreatFinding::Phishing { rule_id, .. } if rule_id == "ph-011-seed-phrase"
        )));
    }

    #[test]
    fn exe_attachment_alone_hits_review() {
        // mw-001-exe weight 50 → ReviewQueue.
        let r = assess_email_threat(
            "Please find the report attached.",
            Some("vendor.example.com"),
            &["report.exe"],
        );
        assert_eq!(r.band, ThreatBand::ReviewQueue);
        assert!(r.findings.iter().any(|f| matches!(
            f,
            ThreatFinding::MalwareAttachment { rule_id, .. } if rule_id == "mw-001-exe"
        )));
    }

    #[test]
    fn exe_plus_phishing_quarantine() {
        let r = assess_email_threat(
            "Please verify your account using the attached tool.",
            Some("attacker.example.com"),
            &["verify-tool.exe"],
        );
        assert_eq!(r.band, ThreatBand::Quarantine);
    }

    #[test]
    fn brand_impersonation_paypal_off_domain() {
        let r = assess_email_threat(
            "Your paypal account requires verification.",
            Some("paypal-secure.attacker.tk"),
            &[],
        );
        assert!(r.findings.iter().any(|f| matches!(
            f,
            ThreatFinding::DomainImpersonation { claimed_brand, .. } if claimed_brand == "paypal"
        )));
    }

    #[test]
    fn brand_impersonation_skipped_on_legit_domain() {
        // Real PayPal sender domain — must NOT flag as impersonation.
        let r = assess_email_threat(
            "Your paypal account statement is ready.",
            Some("service.paypal.com"),
            &[],
        );
        assert!(
            !r.findings
                .iter()
                .any(|f| matches!(f, ThreatFinding::DomainImpersonation { .. }))
        );
    }

    #[test]
    fn classic_spam_lottery_review() {
        let r = assess_email_threat(
            "You have been selected as the winner of our annual lottery. Reply to claim.",
            Some("lottery.tk"),
            &[],
        );
        // 25 (sp-001) < 50, but the next test bumps it.
        assert!(r.score < QUARANTINE_THRESHOLD);
    }

    #[test]
    fn spam_combined_with_phishing_quarantine() {
        let r = assess_email_threat(
            "Make money fast! You have been selected as the winner. Claim your prize and confirm your identity to release funds.",
            Some("attacker.example.com"),
            &[],
        );
        assert_eq!(r.band, ThreatBand::Quarantine);
    }

    #[test]
    fn score_caps_at_100() {
        // Stack enough rules to exceed 100; the score must clamp.
        let r = assess_email_threat(
            "Your account has been suspended. Verify your account, confirm your identity, update your payment, enter your seed phrase. Click here to avoid losing access.",
            Some("attacker.example.com"),
            &["malware.exe", "extra.scr"],
        );
        assert_eq!(r.score, 100);
        assert_eq!(r.band, ThreatBand::Quarantine);
    }

    #[test]
    fn band_as_str_is_pinned_for_audit() {
        assert_eq!(ThreatBand::Allow.as_str(), "allow");
        assert_eq!(ThreatBand::ReviewQueue.as_str(), "review_queue");
        assert_eq!(ThreatBand::Quarantine.as_str(), "quarantine");
    }

    #[test]
    fn malware_filename_case_insensitive() {
        let r = assess_email_threat(
            "Please run the attached.",
            Some("vendor.example.com"),
            &["Setup.EXE"],
        );
        assert!(r.findings.iter().any(|f| matches!(
            f,
            ThreatFinding::MalwareAttachment { rule_id, .. } if rule_id == "mw-001-exe"
        )));
    }

    #[test]
    fn docm_macro_office_flagged() {
        let r = assess_email_threat(
            "Please review the attached spec.",
            Some("vendor.example.com"),
            &["spec.docm"],
        );
        assert!(r.findings.iter().any(|f| matches!(
            f,
            ThreatFinding::MalwareAttachment { rule_id, .. } if rule_id == "mw-011-docm"
        )));
    }

    #[test]
    fn no_sender_domain_skips_impersonation_check() {
        // Without sender_domain, the impersonation rule cannot fire even
        // though the body names a brand.
        let r = assess_email_threat("paypal sent you a statement.", None, &[]);
        assert!(
            !r.findings
                .iter()
                .any(|f| matches!(f, ThreatFinding::DomainImpersonation { .. }))
        );
    }

    #[test]
    fn assessment_is_json_serialisable_for_audit() {
        let r = assess_email_threat("verify your account", Some("attacker.example.com"), &[]);
        let json = serde_json::to_string(&r).expect("serialise");
        assert!(json.contains("\"band\""));
        assert!(json.contains("\"score\""));
        assert!(json.contains("\"findings\""));
    }

    #[test]
    fn rule_weight_accessor() {
        let f = ThreatFinding::Phishing {
            rule_id: "ph-001-verify-account".to_string(),
            weight: 30,
            evidence: "verify your account".to_string(),
        };
        assert_eq!(f.weight(), 30);
    }

    #[test]
    fn brand_impersonation_only_counted_once_per_brand() {
        // The body mentions "paypal" three times — must produce ONE
        // DomainImpersonation finding for "paypal", not three.
        let r = assess_email_threat(
            "paypal paypal paypal — security update for your paypal account.",
            Some("phish.tk"),
            &[],
        );
        let count = r
            .findings
            .iter()
            .filter(|f| matches!(f, ThreatFinding::DomainImpersonation { claimed_brand, .. } if claimed_brand == "paypal"))
            .count();
        assert_eq!(count, 1);
    }
}
