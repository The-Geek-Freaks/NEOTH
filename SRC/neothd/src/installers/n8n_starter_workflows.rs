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
//! ## What each body actually contains (post-2026-05-26 fix)
//!
//! Real n8n-importable JSON, not a placeholder:
//!   - `name` — the workflow's own display name (operator sees in
//!     n8n's workflow list).
//!   - `active: false` — operator GO required (AGENTER hard rule).
//!   - A `scheduleTrigger` node with the spec's cron expression.
//!   - An `httpRequest` node hitting `NEOTH_HTTP_BASE + endpoint`
//!     with an Authorization Bearer header sourced from
//!     `$env.NEOTH_TOKEN`.
//!   - Deterministic node IDs derived from the slug so reimport
//!     produces stable IDs (n8n dedupes on these).
//!   - A `connections` block wiring Schedule → NEOTH HTTP.
//!
//! Drift-guard tests assert each of these properties per workflow
//! (name match, cron match, endpoint match, Schedule→HTTP wiring,
//! Bearer header, slug-derived IDs, **bodies are pairwise distinct
//! across all 10**). See `cfg(test)` block below.
//!
//! ## Why minimal skeletons, not handcrafted production flows
//!
//! Each starter workflow is the SHAPE — Schedule node + NEOTH HTTP
//! request. Operators tune the response-handling chain (format +
//! channel + recipient) post-import. Shipping fancy multi-branch
//! flows would lock operators into our UX preferences; skeletons
//! leave the door open.
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

use std::sync::OnceLock;

use super::n8n_workflows::BootstrapWorkflow;

/// Default NEOTH HTTP base URL the workflows POST/GET against.
/// Operators rewrite this post-import in the n8n UI (e.g. when the
/// daemon binds a non-default port). Kept as a constant so the
/// generator + tests share one source of truth.
pub const NEOTH_HTTP_BASE: &str = "http://localhost:8765";

/// Generate a real n8n-importable workflow JSON. Two nodes:
///
///   1. Schedule trigger with the operator's cron expression.
///   2. HTTP Request hitting `NEOTH_HTTP_BASE + endpoint` with a
///      Bearer token from the `NEOTH_TOKEN` env var.
///
/// Node IDs are derived deterministically from the slug + role so
/// importing the same workflow twice produces stable IDs (n8n
/// dedupes on these). Schedule connects to HTTP via the standard
/// n8n `main` channel.
///
/// `active: false` per the AGENTER "no destructive auto-action
/// without operator GO per command" hard rule — operators
/// explicitly enable in the n8n UI after import.
fn build_workflow_skeleton(slug: &str, name: &str, cron: &str, endpoint: &str) -> String {
    let trigger_id = format!("{slug}_schedule");
    let http_id = format!("{slug}_http");
    let url = format!("{NEOTH_HTTP_BASE}{endpoint}");

    // Build via serde_json so escape rules + valid JSON come for
    // free. The shape matches n8n's import format (workflow → nodes
    // → connections).
    let body = serde_json::json!({
        "name": name,
        "active": false,
        "nodes": [
            {
                "parameters": {
                    "rule": {
                        "interval": [
                            { "field": "cronExpression", "expression": cron }
                        ]
                    }
                },
                "id": trigger_id,
                "name": "Schedule Trigger",
                "type": "n8n-nodes-base.scheduleTrigger",
                "typeVersion": 1,
                "position": [200, 200]
            },
            {
                "parameters": {
                    "url": url,
                    "authentication": "headerAuth",
                    "sendHeaders": true,
                    "headerParameters": {
                        "parameters": [
                            {
                                "name": "Authorization",
                                "value": "Bearer ={{ $env.NEOTH_TOKEN }}"
                            }
                        ]
                    },
                    "options": {}
                },
                "id": http_id,
                "name": "NEOTH HTTP",
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4,
                "position": [500, 200]
            }
        ],
        "connections": {
            "Schedule Trigger": {
                "main": [[
                    { "node": "NEOTH HTTP", "type": "main", "index": 0 }
                ]]
            }
        },
        "settings": {
            "executionOrder": "v1"
        }
    });
    serde_json::to_string(&body).expect("serde_json::Value always serialises")
}

/// Lazy-init the bodies once per process so callers see stable
/// `&'static str` references via `BootstrapWorkflow.body`. Built
/// in slug+name+cron+endpoint order so a future refactor that
/// adds a workflow only touches one place.
fn starter_bodies() -> &'static [&'static str] {
    static BODIES: OnceLock<Vec<&'static str>> = OnceLock::new();
    BODIES
        .get_or_init(|| {
            STARTER_SPECS
                .iter()
                .map(|s| {
                    let body = build_workflow_skeleton(s.slug, s.name, s.cron, s.endpoint);
                    // Leak into 'static once at startup — workflows are
                    // baked into the binary surface anyway; this avoids
                    // every test re-rendering the JSON.
                    let leaked: &'static str = Box::leak(body.into_boxed_str());
                    leaked
                })
                .collect()
        })
        .as_slice()
}

/// One starter-workflow spec. Internal — the public surface stays
/// [`BootstrapWorkflow`] via the lazy `STARTER_WORKFLOWS`
/// accessor.
struct StarterSpec {
    slug: &'static str,
    name: &'static str,
    description: &'static str,
    cron: &'static str,
    endpoint: &'static str,
}

const STARTER_SPECS: &[StarterSpec] = &[
    StarterSpec {
        slug: "paperless_invoice_consult",
        name: "Paperless invoice → consult + draft",
        description: "When paperless-ngx imports a new document, consult the vault for related notes and draft a reply.",
        cron: "*/5 * * * *",
        endpoint: "/paperless/consult",
    },
    StarterSpec {
        slug: "email_threat_quarantine",
        name: "Email threat → review queue",
        description: "Score each new email via PL-05 and route ReviewQueue/Quarantine bands into the proactive review pile.",
        cron: "*/10 * * * *",
        endpoint: "/email/threat/scan",
    },
    StarterSpec {
        slug: "calendar_morning_agenda",
        name: "Calendar morning agenda",
        description: "EM-02 daily agenda: weekdays 08:00 fetch today's events + flag back-to-back conflicts + 5-line summary.",
        cron: "0 8 * * 1-5",
        endpoint: "/calendar/today",
    },
    StarterSpec {
        slug: "proposal_review_reminder",
        name: "Proposal review reminder (24 h)",
        description: "Once a day at 17:00, nudge the operator about OB-03 proposals still in Pending after 24 hours.",
        cron: "0 17 * * *",
        endpoint: "/proactive/proposals/pending",
    },
    StarterSpec {
        slug: "dream_obsidian_sync",
        name: "Dream Obsidian sync (nightly)",
        description: "Every night 02:00, run sync_dreams_to_obsidian for the previous day so the Dreams folder stays fresh.",
        cron: "0 2 * * *",
        endpoint: "/dreaming/sync_obsidian",
    },
    StarterSpec {
        slug: "reflection_weekly_sync",
        name: "Reflection weekly sync",
        description: "Sunday 19:00 — sync_reflections_to_obsidian for the closing ISO week, before the new week starts.",
        cron: "0 19 * * 0",
        endpoint: "/reflection/sync_obsidian",
    },
    StarterSpec {
        slug: "consent_audit_export",
        name: "Consent audit export",
        description: "Weekly export of permission decisions (KF-06 audit scan) to <vault>/Audit/consent-YYYY-WXX.md.",
        cron: "0 20 * * 0",
        endpoint: "/permissions/audit/export",
    },
    StarterSpec {
        slug: "memory_decay_report",
        name: "Memory decay early warning",
        description: "Daily 16:00 — KF-07 drift report; surfaces At-Risk + Imminent memories so the operator can reinforce.",
        cron: "0 16 * * *",
        endpoint: "/memory/drift/report",
    },
    StarterSpec {
        slug: "paperless_threat_alert",
        name: "Paperless prompt-injection alert",
        description: "Watch for PL-04 prompt-injection findings on paperless ingests and proactively alert the operator.",
        cron: "*/15 * * * *",
        endpoint: "/paperless/findings/recent",
    },
    StarterSpec {
        slug: "drafts_pending_review",
        name: "Email drafts pending review (48 h)",
        description: "Nudge twice a day about EM-04 drafts still in Pending after 48 hours so the operator doesn't lose them.",
        cron: "0 9,17 * * *",
        endpoint: "/email/drafts/pending",
    },
];

/// Lazy accessor for the 10 starter workflows. The bodies are built
/// on first access, then cached for the process lifetime.
pub fn starter_workflows() -> &'static [BootstrapWorkflow] {
    static WORKFLOWS: OnceLock<Vec<BootstrapWorkflow>> = OnceLock::new();
    WORKFLOWS
        .get_or_init(|| {
            let bodies = starter_bodies();
            STARTER_SPECS
                .iter()
                .zip(bodies.iter())
                .map(|(s, body)| BootstrapWorkflow {
                    slug: s.slug,
                    name: s.name,
                    description: s.description,
                    body,
                })
                .collect()
        })
        .as_slice()
}

/// Look up a starter workflow by slug — case-sensitive snake_case.
pub fn find_by_slug(slug: &str) -> Option<&'static BootstrapWorkflow> {
    starter_workflows().iter().find(|w| w.slug == slug)
}

/// Convenience: combined `BOOTSTRAP_WORKFLOWS + starter_workflows()`
/// for wizard pickers that show every available workflow in one
/// list. Bootstrap first (always-on), then starter (opt-in).
pub fn all_known_workflows() -> Vec<&'static BootstrapWorkflow> {
    super::n8n_workflows::BOOTSTRAP_WORKFLOWS
        .iter()
        .chain(starter_workflows().iter())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn starter_count_is_pinned_at_ten() {
        assert_eq!(starter_workflows().len(), 10);
        assert_eq!(STARTER_SPECS.len(), 10);
    }

    #[test]
    fn each_starter_has_unique_slug() {
        let mut seen: HashSet<&str> = HashSet::new();
        for w in starter_workflows() {
            assert!(
                seen.insert(w.slug),
                "duplicate slug {:?} in starter_workflows",
                w.slug,
            );
        }
    }

    #[test]
    fn each_starter_has_snake_case_slug() {
        for w in starter_workflows() {
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
        for w in starter_workflows() {
            assert!(
                w.description.len() <= 200,
                "description for {:?} is {} chars (cap 200)",
                w.slug,
                w.description.len(),
            );
        }
    }

    /// Every body must be valid JSON + declare `active: false` (the
    /// AGENTER "no destructive auto-action" rule).
    #[test]
    fn each_starter_body_is_valid_json_and_inactive() {
        for w in starter_workflows() {
            let v: serde_json::Value = serde_json::from_str(w.body)
                .unwrap_or_else(|e| panic!("invalid JSON for {:?}: {e}", w.slug));
            assert_eq!(
                v["active"], false,
                "{:?} must ship inactive",
                w.slug,
            );
        }
    }

    /// Real-skeleton drift guard #1: every body MUST carry the
    /// workflow's name verbatim (Alex flagged 2026-05-26 that the
    /// previous placeholder body claimed "Top-10 starter workflows"
    /// while all 10 bodies were identical).
    #[test]
    fn each_starter_body_contains_its_own_name() {
        for (spec, w) in STARTER_SPECS.iter().zip(starter_workflows().iter()) {
            let v: serde_json::Value = serde_json::from_str(w.body).unwrap();
            assert_eq!(
                v["name"], spec.name,
                "body for {:?} doesn't carry its own name — placeholder regression",
                w.slug,
            );
        }
    }

    /// Real-skeleton drift guard #2: every body MUST embed the
    /// spec's cron expression in a `scheduleTrigger` node so
    /// importing it actually scheduled the workflow.
    #[test]
    fn each_starter_body_embeds_its_cron_in_a_schedule_node() {
        for (spec, w) in STARTER_SPECS.iter().zip(starter_workflows().iter()) {
            let v: serde_json::Value = serde_json::from_str(w.body).unwrap();
            let nodes = v["nodes"].as_array().expect("nodes is array");
            let schedule = nodes
                .iter()
                .find(|n| n["type"] == "n8n-nodes-base.scheduleTrigger")
                .unwrap_or_else(|| {
                    panic!(
                        "no scheduleTrigger node in {:?}: {}",
                        spec.slug, w.body,
                    )
                });
            let expression = schedule["parameters"]["rule"]["interval"][0]
                ["expression"]
                .as_str()
                .unwrap_or_else(|| panic!("missing cron expression in {:?}", spec.slug));
            assert_eq!(
                expression, spec.cron,
                "body for {:?} has wrong cron",
                spec.slug,
            );
        }
    }

    /// Real-skeleton drift guard #3: every body MUST embed the
    /// spec's NEOTH HTTP endpoint in an `httpRequest` node so the
    /// trigger actually calls back into the daemon.
    #[test]
    fn each_starter_body_embeds_its_endpoint_in_an_http_node() {
        for (spec, w) in STARTER_SPECS.iter().zip(starter_workflows().iter()) {
            let v: serde_json::Value = serde_json::from_str(w.body).unwrap();
            let nodes = v["nodes"].as_array().expect("nodes is array");
            let http = nodes
                .iter()
                .find(|n| n["type"] == "n8n-nodes-base.httpRequest")
                .unwrap_or_else(|| {
                    panic!("no httpRequest node in {:?}", spec.slug)
                });
            let url = http["parameters"]["url"]
                .as_str()
                .unwrap_or_else(|| panic!("missing url in {:?}", spec.slug));
            let expected = format!("{NEOTH_HTTP_BASE}{}", spec.endpoint);
            assert_eq!(url, expected, "body for {:?} has wrong URL", spec.slug);
        }
    }

    /// Real-skeleton drift guard #4: every body MUST wire the
    /// Schedule → NEOTH-HTTP connection so the trigger actually
    /// reaches the HTTP call.
    #[test]
    fn each_starter_body_connects_schedule_to_http() {
        for w in starter_workflows() {
            let v: serde_json::Value = serde_json::from_str(w.body).unwrap();
            let conn = &v["connections"]["Schedule Trigger"]["main"][0][0];
            assert_eq!(
                conn["node"], "NEOTH HTTP",
                "{:?} Schedule→HTTP wiring missing",
                w.slug,
            );
        }
    }

    /// Real-skeleton drift guard #5: every body MUST carry an
    /// Authorization Bearer header sourced from NEOTH_TOKEN env so
    /// the daemon authenticates the call (not anonymous).
    #[test]
    fn each_starter_body_carries_bearer_auth_header() {
        for w in starter_workflows() {
            assert!(
                w.body.contains("Authorization"),
                "{:?} missing Authorization header",
                w.slug,
            );
            assert!(
                w.body.contains("NEOTH_TOKEN"),
                "{:?} missing NEOTH_TOKEN env reference",
                w.slug,
            );
        }
    }

    /// Real-skeleton drift guard #6: every body's two node IDs MUST
    /// derive from the slug so reimport produces stable IDs (n8n
    /// dedupes on these).
    #[test]
    fn each_starter_body_node_ids_derive_from_slug() {
        for (spec, w) in STARTER_SPECS.iter().zip(starter_workflows().iter()) {
            let v: serde_json::Value = serde_json::from_str(w.body).unwrap();
            let nodes = v["nodes"].as_array().unwrap();
            let ids: Vec<&str> = nodes.iter().map(|n| n["id"].as_str().unwrap()).collect();
            assert!(
                ids.iter().any(|id| id.starts_with(spec.slug)),
                "{:?}: no node id starts with slug — IDs: {:?}",
                spec.slug,
                ids,
            );
        }
    }

    /// Real-skeleton drift guard #7: bodies MUST differ across
    /// workflows (the regression Alex flagged was identical bodies
    /// for all 10). Pairwise check.
    #[test]
    fn starter_bodies_are_distinct_across_workflows() {
        let bodies: Vec<&str> = starter_workflows().iter().map(|w| w.body).collect();
        let unique: HashSet<&str> = bodies.iter().copied().collect();
        assert_eq!(
            bodies.len(),
            unique.len(),
            "duplicate bodies in starter set — placeholder regression",
        );
    }

    #[test]
    fn neoth_http_base_pinned() {
        // Drift guard — n8n workflows are baked at compile time;
        // if a future PR changes this constant, every body changes
        // + the operator must re-import. Pin to catch unintended drift.
        assert_eq!(NEOTH_HTTP_BASE, "http://localhost:8765");
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
                + starter_workflows().len(),
        );
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
        for w in starter_workflows() {
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
        let actual: Vec<&str> = starter_workflows().iter().map(|w| w.slug).collect();
        assert_eq!(actual, expected);
    }

    /// Tests for the build_workflow_skeleton fn itself so future
    /// changes to the helper don't silently break the 10 starters.
    #[test]
    fn build_workflow_skeleton_embeds_name_cron_endpoint() {
        let json = build_workflow_skeleton(
            "test_slug",
            "Test Workflow",
            "*/5 * * * *",
            "/test/endpoint",
        );
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["name"], "Test Workflow");
        assert_eq!(v["active"], false);
        let nodes = v["nodes"].as_array().unwrap();
        let schedule = nodes
            .iter()
            .find(|n| n["type"] == "n8n-nodes-base.scheduleTrigger")
            .unwrap();
        assert_eq!(
            schedule["parameters"]["rule"]["interval"][0]["expression"],
            "*/5 * * * *",
        );
        let http = nodes
            .iter()
            .find(|n| n["type"] == "n8n-nodes-base.httpRequest")
            .unwrap();
        assert_eq!(http["parameters"]["url"], "http://localhost:8765/test/endpoint");
    }

    #[test]
    fn build_workflow_skeleton_node_ids_use_slug() {
        let json = build_workflow_skeleton("my_slug", "x", "* * * * *", "/x");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let ids: Vec<&str> = v["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["id"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&"my_slug_schedule"));
        assert!(ids.contains(&"my_slug_http"));
    }

    #[test]
    fn build_workflow_skeleton_distinct_outputs_for_distinct_inputs() {
        let a = build_workflow_skeleton("a", "Aaa", "0 * * * *", "/a");
        let b = build_workflow_skeleton("b", "Bbb", "0 * * * *", "/b");
        assert_ne!(a, b);
    }
}
