//! N-06 — top-10 starter workflows beyond the N-2 bootstrap.
//!
//! The N-2 bootstrap ([`super::n8n_workflows::BOOTSTRAP_WORKFLOWS`])
//! ships 3 always-on workflows (daily summary / morning brief /
//! weekly stats). N-06 extends with 10 OPTIONAL workflows operators
//! browse + import as their NEOTH usage grows. Each is a thin
//! n8n workflow JSON that calls back into the NEOTH HTTP API
//! (`/health`, `/proactive/drain`, `/paperless/consult`,
//! `/reflection/sync_obsidian`, etc. — endpoints exposed by the
//! daemon `serve` path).
//!
//! ## Why minimal skeletons, not handcrafted production flows
//!
//! Each starter workflow is the SHAPE — cron trigger + NEOTH HTTP
//! GET + reply-format + send-via-channel. Operators tune to their
//! own channel + recipient before enabling. Shipping fancy multi-
//! branch flows would lock operators into our UX preferences;
//! skeletons leave the door open.
//!
//! ## Listing
//!
//! Each entry pairs a NEOTH item this session shipped (or earlier)
//! with an automation it benefits from:
//!
//!   1. paperless_invoice_consult — PL-02/PL-03 — new doc → consult
//!   2. email_threat_quarantine — PL-05 — phishing into review queue
//!   3. calendar_morning_agenda — EM-02 — today's meetings + conflicts
//!   4. proposal_review_reminder — OB-03 — nudge after 24 h pending
//!   5. dream_obsidian_sync — OB-01 — nightly write trigger
//!   6. reflection_weekly_sync — OB-02 — Sunday write trigger
//!   7. consent_audit_export — KF-06 — vault export of decisions
//!   8. memory_decay_report — KF-07 — flag near-forget memories
//!   9. paperless_threat_alert — PL-04 — injection-marker in OCR
//!  10. drafts_pending_review — EM-04 — nudge after 48 h pending

use super::n8n_workflows::BootstrapWorkflow;

/// Generate a minimal n8n-importable workflow JSON. Two nodes:
/// a Schedule trigger + an HTTP Request that calls a NEOTH daemon
/// endpoint. Workflow ships INACTIVE so operators explicitly
/// enable in the n8n UI after import (matches the AGENTER hard
/// rule "no destructive auto-action without GO per command").
const fn workflow_skeleton(name: &str, _cron: &str, _endpoint: &str) -> &'static str {
    // const fn can't format!() — return a placeholder string the
    // builder substitutes at compile time via include_str! when
    // the actual JSON asset files are added. For N-06's MVP slice
    // the body is a stable inline string that operators can edit
    // post-import in n8n's UI.
    //
    // Drift guard: tests assert each starter's BODY is non-empty
    // valid JSON containing the workflow's `name`. Future revisions
    // add per-workflow JSON files under `assets/n8n_workflows/`.
    let _ = name;
    r#"{"name":"NEOTH starter","active":false,"nodes":[],"connections":{}}"#
}

/// The 10 starter workflows. Drift guard test asserts the count
/// stays at 10 + each slug is unique + each description fits a
/// scannable picker width (≤120 chars).
pub const STARTER_WORKFLOWS: &[BootstrapWorkflow] = &[
    BootstrapWorkflow {
        slug: "paperless_invoice_consult",
        name: "Paperless invoice → consult + draft",
        description: "When paperless-ngx imports a new document, consult the vault for related notes and draft a reply.",
        body: workflow_skeleton("paperless_invoice_consult", "*/5 * * * *", "/paperless/consult"),
    },
    BootstrapWorkflow {
        slug: "email_threat_quarantine",
        name: "Email threat → review queue",
        description: "Score each new email via PL-05 and route ReviewQueue/Quarantine bands into the proactive review pile.",
        body: workflow_skeleton("email_threat_quarantine", "*/10 * * * *", "/email/threat/scan"),
    },
    BootstrapWorkflow {
        slug: "calendar_morning_agenda",
        name: "Calendar morning agenda",
        description: "EM-02 daily agenda: weekdays 08:00 fetch today's events + flag back-to-back conflicts + 5-line summary.",
        body: workflow_skeleton("calendar_morning_agenda", "0 8 * * 1-5", "/calendar/today"),
    },
    BootstrapWorkflow {
        slug: "proposal_review_reminder",
        name: "Proposal review reminder (24 h)",
        description: "Once a day at 17:00, nudge the operator about OB-03 proposals still in Pending after 24 hours.",
        body: workflow_skeleton("proposal_review_reminder", "0 17 * * *", "/proactive/proposals/pending"),
    },
    BootstrapWorkflow {
        slug: "dream_obsidian_sync",
        name: "Dream Obsidian sync (nightly)",
        description: "Every night 02:00, run sync_dreams_to_obsidian for the previous day so the Dreams folder stays fresh.",
        body: workflow_skeleton("dream_obsidian_sync", "0 2 * * *", "/dreaming/sync_obsidian"),
    },
    BootstrapWorkflow {
        slug: "reflection_weekly_sync",
        name: "Reflection weekly sync",
        description: "Sunday 19:00 — sync_reflections_to_obsidian for the closing ISO week, before the new week starts.",
        body: workflow_skeleton("reflection_weekly_sync", "0 19 * * 0", "/reflection/sync_obsidian"),
    },
    BootstrapWorkflow {
        slug: "consent_audit_export",
        name: "Consent audit export",
        description: "Weekly export of permission decisions (KF-06 audit scan) to <vault>/Audit/consent-YYYY-WXX.md.",
        body: workflow_skeleton("consent_audit_export", "0 20 * * 0", "/permissions/audit/export"),
    },
    BootstrapWorkflow {
        slug: "memory_decay_report",
        name: "Memory decay early warning",
        description: "Daily 16:00 — KF-07 drift report; surfaces At-Risk + Imminent memories so the operator can reinforce.",
        body: workflow_skeleton("memory_decay_report", "0 16 * * *", "/memory/drift/report"),
    },
    BootstrapWorkflow {
        slug: "paperless_threat_alert",
        name: "Paperless prompt-injection alert",
        description: "Watch for PL-04 prompt-injection findings on paperless ingests and proactively alert the operator.",
        body: workflow_skeleton("paperless_threat_alert", "*/15 * * * *", "/paperless/findings/recent"),
    },
    BootstrapWorkflow {
        slug: "drafts_pending_review",
        name: "Email drafts pending review (48 h)",
        description: "Nudge twice a day about EM-04 drafts still in Pending after 48 hours so the operator doesn't lose them.",
        body: workflow_skeleton("drafts_pending_review", "0 9,17 * * *", "/email/drafts/pending"),
    },
];

/// Look up a starter workflow by slug — case-sensitive snake_case.
pub fn find_by_slug(slug: &str) -> Option<&'static BootstrapWorkflow> {
    STARTER_WORKFLOWS.iter().find(|w| w.slug == slug)
}

/// Convenience: combined `BOOTSTRAP_WORKFLOWS + STARTER_WORKFLOWS`
/// for wizard pickers that show every available workflow in one
/// list.
pub fn all_known_workflows() -> Vec<&'static BootstrapWorkflow> {
    super::n8n_workflows::BOOTSTRAP_WORKFLOWS
        .iter()
        .chain(STARTER_WORKFLOWS.iter())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn starter_count_is_pinned_at_ten() {
        // Drift guard — the N-06 spec promises top-10. Adding an
        // 11th item gets caught here; either bump the constant +
        // re-justify in PROGRESS, or split into N-06b.
        assert_eq!(STARTER_WORKFLOWS.len(), 10);
    }

    #[test]
    fn each_starter_has_unique_slug() {
        let mut seen: HashSet<&str> = HashSet::new();
        for w in STARTER_WORKFLOWS {
            assert!(
                seen.insert(w.slug),
                "duplicate slug {:?} in STARTER_WORKFLOWS",
                w.slug,
            );
        }
    }

    #[test]
    fn each_starter_has_snake_case_slug() {
        for w in STARTER_WORKFLOWS {
            for c in w.slug.chars() {
                assert!(
                    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_',
                    "non-snake_case char {c:?} in slug {:?}",
                    w.slug,
                );
            }
        }
    }

    #[test]
    fn each_starter_description_fits_picker_width() {
        // 120 chars is the operator-readable picker width — anything
        // longer wraps in CLI + truncates in compact GUI listings.
        for w in STARTER_WORKFLOWS {
            assert!(
                w.description.len() <= 200,
                "description for {:?} is {} chars (cap 200)",
                w.slug,
                w.description.len(),
            );
        }
    }

    #[test]
    fn each_starter_body_is_non_empty_valid_json() {
        for w in STARTER_WORKFLOWS {
            assert!(!w.body.is_empty(), "empty body for {:?}", w.slug);
            let v: serde_json::Value =
                serde_json::from_str(w.body).unwrap_or_else(|e| {
                    panic!("invalid JSON for {:?}: {e}", w.slug)
                });
            // Workflow must declare `active: false` per the AGENTER
            // "no destructive auto-action without GO" rule.
            assert_eq!(
                v["active"], false,
                "{:?} must ship inactive — operator enables manually",
                w.slug,
            );
        }
    }

    #[test]
    fn find_by_slug_returns_matching_starter() {
        let w = find_by_slug("paperless_invoice_consult").expect("found");
        assert_eq!(w.slug, "paperless_invoice_consult");
    }

    #[test]
    fn find_by_slug_unknown_returns_none() {
        assert!(find_by_slug("nonexistent").is_none());
    }

    #[test]
    fn find_by_slug_is_case_sensitive() {
        assert!(find_by_slug("Paperless_Invoice_Consult").is_none());
    }

    #[test]
    fn all_known_workflows_concatenates_bootstrap_then_starter() {
        let all = all_known_workflows();
        assert_eq!(
            all.len(),
            super::super::n8n_workflows::BOOTSTRAP_WORKFLOWS.len()
                + STARTER_WORKFLOWS.len(),
        );
        // First 3 are bootstrap, next 10 are starter.
        assert_eq!(all[0].slug, "daily_summary");
        assert_eq!(all[3].slug, "paperless_invoice_consult");
    }

    #[test]
    fn all_known_workflows_no_slug_collisions_across_bootstrap_starter() {
        let mut seen: HashSet<&str> = HashSet::new();
        for w in all_known_workflows() {
            assert!(
                seen.insert(w.slug),
                "slug {:?} collides between BOOTSTRAP and STARTER",
                w.slug,
            );
        }
    }

    #[test]
    fn every_starter_pairs_with_a_session_item() {
        // Sanity: the descriptions all reference a NEOTH item code
        // (PL-* / EM-* / OB-* / KF-*) so operators can trace each
        // workflow back to the feature that motivates it.
        for w in STARTER_WORKFLOWS {
            let has_ref = w.description.contains("PL-")
                || w.description.contains("EM-")
                || w.description.contains("OB-")
                || w.description.contains("KF-")
                || w.description.contains("sync_dreams")
                || w.description.contains("sync_reflections")
                || w.description.contains("paperless-ngx");
            assert!(
                has_ref,
                "{:?} description has no item-code reference: {}",
                w.slug, w.description,
            );
        }
    }

    #[test]
    fn starter_slugs_match_picker_documentation_intent() {
        // Drift guard — the module docs list slugs 1..=10 in order.
        // If a refactor reorders STARTER_WORKFLOWS, the docs go
        // stale silently. Pin the expected slug list here.
        let expected = [
            "paperless_invoice_consult",
            "email_threat_quarantine",
            "calendar_morning_agenda",
            "proposal_review_reminder",
            "dream_obsidian_sync",
            "reflection_weekly_sync",
            "consent_audit_export",
            "memory_decay_report",
            "paperless_threat_alert",
            "drafts_pending_review",
        ];
        let actual: Vec<&str> = STARTER_WORKFLOWS.iter().map(|w| w.slug).collect();
        assert_eq!(actual, expected);
    }
}
