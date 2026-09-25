//! N-06 — top-10 starter workflows beyond the N-2 bootstrap.
//!
//! The N-2 bootstrap ([`super::n8n_workflows::BOOTSTRAP_WORKFLOWS`])
//! ships 3 inactive bootstrap workflow templates (daily summary / morning brief /
//! weekly stats). N-06 extends with 10 OPTIONAL workflows operators
//! browse + import as their NEOTH usage grows. Each is a thin
//! n8n workflow JSON that references a NEOTH HTTP API path
//! (`/health`, `/proactive/drain`, `/paperless/consult`,
//! `/reflection/sync_obsidian`, etc.). Route availability and container-to-host
//! reachability are separate deployment checks.
//!
//! ## What each body actually contains (post-2026-05-26 fix)
//!
//! Real n8n-importable JSON, not a placeholder:
//!   - `name` — the workflow's own display name (operator sees in
//!     n8n's workflow list).
//!   - `active: false` — operator GO required (AGENTER hard rule).
//!   - A `scheduleTrigger` node with the spec's cron expression.
//!   - A visible operator configuration node for a reachable NEOTH
//!     origin and an HTTP Request node that uses an operator-bound
//!     HTTP Header Auth credential.
//!   - Deterministic node IDs derived from the slug for stable local
//!     workflow shape. Public workflow POSTs do not deduplicate on node IDs.
//!   - A connections block wiring Schedule → Configuration → NEOTH HTTP.
//!
//! Drift-guard tests assert each of these properties per workflow
//! (name match, cron match, endpoint match, Schedule→Configuration→HTTP wiring,
//! credential configuration, slug-derived IDs, **bodies are pairwise distinct
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

/// Visible non-secret origin placeholder for generated n8n workflows.
/// The loopback-only n8n API normally listens on port 9744, but an n8n
/// container needs an operator-configured reachable origin; localhost is not
/// a universal container-to-host bridge.
pub const NEOTH_HTTP_BASE: &str = "http://REPLACE_WITH_NEOTH_HOST:9744";

/// Generate a real n8n-importable workflow JSON. Three nodes:
///
///   1. Schedule trigger with the operator's cron expression.
///   2. Operator Configuration with a visible non-secret NEOTH origin.
///   3. HTTP Request hitting the configured origin + endpoint with a
///      generic HTTP Header Auth credential selected after import.
///
/// Node IDs are derived deterministically from the slug + role for a stable
/// workflow shape. They do not make public workflow POSTs idempotent. Schedule
/// connects to HTTP via the standard n8n `main` channel.
///
/// `active: false` per the AGENTER "no destructive auto-action
/// without operator GO per command" hard rule — operators
/// explicitly enable in the n8n UI after import.
fn build_workflow_skeleton(
    slug: &str,
    name: &str,
    cron: &str,
    endpoint: &str,
    method: &str,
) -> String {
    let trigger_id = format!("{slug}_schedule");
    let configuration_id = format!("{slug}_configuration");
    let http_id = format!("{slug}_http");
    let url = format!("={{{{ $json.neothBaseUrl + '{endpoint}' }}}}");
    let unavailable_note = format!(
        "Unavailable starter intent: {endpoint} is not one of the nine current NEOTH n8n API routes. Keep this workflow inactive until an explicit adapter and its request-payload contract are implemented; no payload adapter is shipped here."
    );
    let (http_parameters, http_note) = if slug == "memory_decay_report" {
        (
            serde_json::json!({
                "url": url,
                "method": method,
                "authentication": "genericCredentialType",
                "genericAuthType": "httpHeaderAuth",
                "sendBody": true,
                "contentType": "json",
                "specifyBody": "json",
                "jsonBody": "={{ JSON.stringify({ limit: 20 }) }}",
                "options": {}
            }),
            "Implemented POST /api/memory/drift reads the existing views.db projection with recall:read scope. It returns bounded drift rows and exact counts without creating, migrating, or modifying the database.",
        )
    } else if slug == "proposal_review_reminder" {
        (
            serde_json::json!({
                "url": url,
                "method": method,
                "authentication": "genericCredentialType",
                "genericAuthType": "httpHeaderAuth",
                "sendBody": true,
                "contentType": "json",
                "specifyBody": "json",
                "jsonBody": "={{ JSON.stringify({ limit: 20, min_age_secs: 86400 }) }}",
                "options": {}
            }),
            "Implemented POST /api/proactive/proposals/pending requires proposals:read and returns metadata for pending proposals at least 24 hours old. Draft YAML, rationale and operator notes stay in NEOTH; this workflow does not approve or apply proposals.",
        )
    } else if slug == "drafts_pending_review" {
        (
            serde_json::json!({
                "url": url,
                "method": method,
                "authentication": "genericCredentialType",
                "genericAuthType": "httpHeaderAuth",
                "sendBody": true,
                "contentType": "json",
                "specifyBody": "json",
                "jsonBody": "={{ JSON.stringify({ limit: 20, min_age_secs: 172800 }) }}",
                "options": {}
            }),
            "Implemented POST /api/email/drafts/pending requires drafts:read and returns pending draft reminder metadata at least 48 hours old. Recipient address, brief, signature and snippets stay in NEOTH; this workflow does not review, send or discard drafts.",
        )
    } else {
        (
            serde_json::json!({
                "url": url,
                "method": method,
                "authentication": "genericCredentialType",
                "genericAuthType": "httpHeaderAuth",
                "options": {}
            }),
            unavailable_note.as_str(),
        )
    };

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
                "position": [0, 200],
                "notesInFlow": true,
                "notes": "Inactive after import. The schedule only runs after the operator configures and explicitly activates this workflow."
            },
            {
                "parameters": {
                    "mode": "manual",
                    "assignments": {
                        "assignments": [
                            {
                                "id": format!("{slug}_neoth_base_url"),
                                "name": "neothBaseUrl",
                                "type": "string",
                                "value": NEOTH_HTTP_BASE
                            }
                        ]
                    },
                    "options": {}
                },
                "id": configuration_id,
                "name": "Operator Configuration",
                "type": "n8n-nodes-base.set",
                "typeVersion": 3.5,
                "position": [220, 200],
                "notesInFlow": true,
                "notes": "Set neothBaseUrl to an address reachable from the n8n runtime. The NEOTH n8n API is loopback-only; 127.0.0.1 works only when n8n shares its host network. Bind an HTTP Header Auth credential with Authorization: Bearer <NEOTH n8n API token> on the request node before activation."
            },
            {
                "parameters": http_parameters,
                "id": http_id,
                "name": "NEOTH HTTP",
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4,
                "position": [460, 200],
                "notesInFlow": true,
                "notes": http_note
            }
        ],
        "connections": {
            "Schedule Trigger": {
                "main": [[
                    { "node": "Operator Configuration", "type": "main", "index": 0 }
                ]]
            },
            "Operator Configuration": {
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
                    let body =
                        build_workflow_skeleton(s.slug, s.name, s.cron, s.endpoint, s.method);
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
    method: &'static str,
}

const STARTER_SPECS: &[StarterSpec] = &[
    StarterSpec {
        slug: "paperless_invoice_consult",
        name: "Paperless invoice → consult + draft",
        description: "Unavailable adapter: intended PL-02/PL-03 paperless-ngx consult and draft workflow.",
        cron: "*/5 * * * *",
        endpoint: "/paperless/consult",
        method: "POST",
    },
    StarterSpec {
        slug: "email_threat_quarantine",
        name: "Email threat → review queue",
        description: "Unavailable adapter: intended PL-05 email threat scan and review-queue workflow.",
        cron: "*/10 * * * *",
        endpoint: "/email/threat/scan",
        method: "POST",
    },
    StarterSpec {
        slug: "calendar_morning_agenda",
        name: "Calendar morning agenda",
        description: "Unavailable adapter: intended EM-02 weekday agenda and conflict-summary workflow.",
        cron: "0 8 * * 1-5",
        endpoint: "/calendar/today",
        method: "GET",
    },
    StarterSpec {
        slug: "proposal_review_reminder",
        name: "Proposal review reminder (24 h)",
        description: "Read pending proposal metadata after 24 hours; review and approval remain in NEOTH.",
        cron: "0 17 * * *",
        endpoint: "/api/proactive/proposals/pending",
        method: "POST",
    },
    StarterSpec {
        slug: "dream_obsidian_sync",
        name: "Dream Obsidian sync (nightly)",
        description: "Unavailable adapter: intended nightly sync_dreams_to_obsidian workflow.",
        cron: "0 2 * * *",
        endpoint: "/dreaming/sync_obsidian",
        method: "POST",
    },
    StarterSpec {
        slug: "reflection_weekly_sync",
        name: "Reflection weekly sync",
        description: "Unavailable adapter: intended weekly sync_reflections_to_obsidian workflow.",
        cron: "0 19 * * 0",
        endpoint: "/reflection/sync_obsidian",
        method: "POST",
    },
    StarterSpec {
        slug: "consent_audit_export",
        name: "Consent audit export",
        description: "Unavailable adapter: intended KF-06 permission-decision audit export workflow.",
        cron: "0 20 * * 0",
        endpoint: "/permissions/audit/export",
        method: "POST",
    },
    StarterSpec {
        slug: "memory_decay_report",
        name: "Memory decay early warning",
        description: "Daily KF-07 memory-drift report from NEOTH's read-only views projection.",
        cron: "0 16 * * *",
        endpoint: "/api/memory/drift",
        method: "POST",
    },
    StarterSpec {
        slug: "paperless_threat_alert",
        name: "Paperless prompt-injection alert",
        description: "Unavailable adapter: intended PL-04 paperless prompt-injection alert workflow.",
        cron: "*/15 * * * *",
        endpoint: "/paperless/findings/recent",
        method: "GET",
    },
    StarterSpec {
        slug: "drafts_pending_review",
        name: "Email drafts pending review (48 h)",
        description: "Read pending email-draft metadata after 48 hours; review and sending remain in NEOTH.",
        cron: "0 9,17 * * *",
        endpoint: "/api/email/drafts/pending",
        method: "POST",
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
/// list. Bootstrap first (inactive), then starter (opt-in).
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
            assert_eq!(v["active"], false, "{:?} must ship inactive", w.slug,);
        }
    }

    /// Real-skeleton drift guard #1: every body MUST carry the
    /// workflow's name verbatim (regression: the previous placeholder
    /// body claimed "Top-10 starter workflows" while all 10 bodies
    /// were identical).
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
    /// spec's cron expression in a `scheduleTrigger` node. Activation remains
    /// an explicit operator action after import.
    #[test]
    fn each_starter_body_embeds_its_cron_in_a_schedule_node() {
        for (spec, w) in STARTER_SPECS.iter().zip(starter_workflows().iter()) {
            let v: serde_json::Value = serde_json::from_str(w.body).unwrap();
            let nodes = v["nodes"].as_array().expect("nodes is array");
            let schedule = nodes
                .iter()
                .find(|n| n["type"] == "n8n-nodes-base.scheduleTrigger")
                .unwrap_or_else(|| {
                    panic!("no scheduleTrigger node in {:?}: {}", spec.slug, w.body,)
                });
            let expression = schedule["parameters"]["rule"]["interval"][0]["expression"]
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
    /// spec's intended NEOTH HTTP endpoint in an `httpRequest` node. This does
    /// not assert route availability or container-to-host reachability.
    #[test]
    fn each_starter_body_embeds_its_endpoint_in_an_http_node() {
        for (spec, w) in STARTER_SPECS.iter().zip(starter_workflows().iter()) {
            let v: serde_json::Value = serde_json::from_str(w.body).unwrap();
            let nodes = v["nodes"].as_array().expect("nodes is array");
            let http = nodes
                .iter()
                .find(|n| n["type"] == "n8n-nodes-base.httpRequest")
                .unwrap_or_else(|| panic!("no httpRequest node in {:?}", spec.slug));
            let url = http["parameters"]["url"]
                .as_str()
                .unwrap_or_else(|| panic!("missing url in {:?}", spec.slug));
            let expected = ["={{ $json.neothBaseUrl + '", spec.endpoint, "' }}"].concat();
            assert_eq!(url, expected, "body for {:?} has wrong URL", spec.slug);
            assert_eq!(
                http["parameters"]["method"], spec.method,
                "body for {:?} has wrong HTTP method",
                spec.slug,
            );
        }
    }

    /// Real-skeleton drift guard #4: every body MUST wire the
    /// Schedule → Configuration → NEOTH-HTTP connection so an activated
    /// workflow carries the visible operator origin into the request.
    #[test]
    fn each_starter_body_connects_schedule_configuration_and_http() {
        for w in starter_workflows() {
            let v: serde_json::Value = serde_json::from_str(w.body).unwrap();
            let schedule_conn = &v["connections"]["Schedule Trigger"]["main"][0][0];
            assert_eq!(
                schedule_conn["node"], "Operator Configuration",
                "{:?} Schedule→Configuration wiring missing",
                w.slug,
            );
            let configuration_conn = &v["connections"]["Operator Configuration"]["main"][0][0];
            assert_eq!(
                configuration_conn["node"], "NEOTH HTTP",
                "{:?} Configuration→HTTP wiring missing",
                w.slug,
            );
        }
    }

    /// Real-skeleton drift guard #5: every body MUST use the n8n generic
    /// HTTP Header Auth credential selector, never a blocked environment
    /// expression or a raw Authorization header.
    #[test]
    fn each_starter_body_uses_generic_header_auth_and_visible_origin() {
        for w in starter_workflows() {
            let v: serde_json::Value = serde_json::from_str(w.body).unwrap();
            let nodes = v["nodes"].as_array().expect("nodes is array");
            let configuration = nodes
                .iter()
                .find(|n| n["type"] == "n8n-nodes-base.set")
                .unwrap_or_else(|| panic!("missing configuration node in {:?}", w.slug));
            assert_eq!(configuration["typeVersion"].as_f64(), Some(3.5));
            assert_eq!(configuration["parameters"]["mode"], "manual");
            assert_eq!(
                configuration["parameters"]["assignments"]["assignments"][0]["name"],
                "neothBaseUrl",
            );
            assert_eq!(
                configuration["parameters"]["assignments"]["assignments"][0]["value"],
                NEOTH_HTTP_BASE,
            );
            let http = nodes
                .iter()
                .find(|n| n["type"] == "n8n-nodes-base.httpRequest")
                .unwrap_or_else(|| panic!("missing HTTP node in {:?}", w.slug));
            assert!(
                http["parameters"]["authentication"] == "genericCredentialType",
                "{:?} missing generic credential auth",
                w.slug,
            );
            assert!(
                http["parameters"]["genericAuthType"] == "httpHeaderAuth",
                "{:?} missing HTTP Header Auth selector",
                w.slug,
            );
            assert!(
                !w.body.contains("NEOTH_TOKEN"),
                "{:?} leaks env auth",
                w.slug
            );
            assert!(
                !w.body.contains("$env"),
                "{:?} leaks env expression",
                w.slug
            );
            if w.slug == "memory_decay_report" {
                assert_eq!(http["parameters"]["method"], "POST");
                assert_eq!(http["parameters"]["sendBody"], true);
                assert_eq!(http["parameters"]["contentType"], "json");
                assert_eq!(http["parameters"]["specifyBody"], "json");
                assert_eq!(
                    http["parameters"]["jsonBody"],
                    "={{ JSON.stringify({ limit: 20 }) }}",
                );
                assert!(
                    http["notes"]
                        .as_str()
                        .is_some_and(|notes| notes.contains("Implemented POST /api/memory/drift")),
                    "implemented drift starter must identify its supported route",
                );
            } else if w.slug == "proposal_review_reminder" {
                assert_eq!(http["parameters"]["method"], "POST");
                assert_eq!(http["parameters"]["sendBody"], true);
                assert_eq!(
                    http["parameters"]["jsonBody"],
                    "={{ JSON.stringify({ limit: 20, min_age_secs: 86400 }) }}"
                );
                assert!(
                    http["notes"]
                        .as_str()
                    .is_some_and(|notes| notes.contains("requires proposals:read"))
                );
            } else if w.slug == "drafts_pending_review" {
                assert_eq!(http["parameters"]["method"], "POST");
                assert_eq!(http["parameters"]["sendBody"], true);
                assert_eq!(http["parameters"]["contentType"], "json");
                assert_eq!(http["parameters"]["specifyBody"], "json");
                assert_eq!(
                    http["parameters"]["jsonBody"],
                    "={{ JSON.stringify({ limit: 20, min_age_secs: 172800 }) }}"
                );
                assert!(
                    http["notes"]
                        .as_str()
                        .is_some_and(|notes| notes.contains("requires drafts:read"))
                );
            } else {
                assert!(
                    http["notes"]
                        .as_str()
                        .is_some_and(|notes| notes.contains("Unavailable starter intent")),
                    "{:?} must disclose unavailable adapter status",
                    w.slug,
                );
            }
        }
    }

    /// Real-skeleton drift guard #6: every body's node IDs MUST
    /// derive from the slug for stable local workflow shape; node IDs do not
    /// deduplicate public workflow POSTs.
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
    /// workflows (regression: identical bodies for all 10 was the
    /// original placeholder bug). Pairwise check.
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
        assert_eq!(NEOTH_HTTP_BASE, "http://REPLACE_WITH_NEOTH_HOST:9744");
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
            super::super::n8n_workflows::BOOTSTRAP_WORKFLOWS.len() + starter_workflows().len(),
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
            "POST",
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
        assert_eq!(
            http["parameters"]["url"],
            "={{ $json.neothBaseUrl + '/test/endpoint' }}"
        );
        assert_eq!(http["parameters"]["method"], "POST");
        assert_eq!(
            http["parameters"]["authentication"],
            "genericCredentialType"
        );
        assert_eq!(http["parameters"]["genericAuthType"], "httpHeaderAuth");
    }

    #[test]
    fn build_workflow_skeleton_node_ids_use_slug() {
        let json = build_workflow_skeleton("my_slug", "x", "* * * * *", "/x", "GET");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let ids: Vec<&str> = v["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["id"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&"my_slug_schedule"));
        assert!(ids.contains(&"my_slug_configuration"));
        assert!(ids.contains(&"my_slug_http"));
    }

    #[test]
    fn build_workflow_skeleton_distinct_outputs_for_distinct_inputs() {
        let a = build_workflow_skeleton("a", "Aaa", "0 * * * *", "/a", "GET");
        let b = build_workflow_skeleton("b", "Bbb", "0 * * * *", "/b", "GET");
        assert_ne!(a, b);
    }
}
