//! N-06 — top-10 starter workflows beyond the N-2 bootstrap.
//!
//! The N-2 bootstrap ([`super::n8n_workflows::BOOTSTRAP_WORKFLOWS`])
//! ships 3 inactive bootstrap workflow templates (daily summary / morning brief /
//! weekly stats). N-06 extends with 10 OPTIONAL workflows operators
//! browse + import as their NEOTH usage grows. Each is a thin
//! n8n workflow JSON that references a NEOTH HTTP API path
//! (`/health`, `/proactive/drain`, `/api/paperless/consult`,
//! `/reflection/sync_obsidian`, etc.). Route availability and container-to-host
//! reachability are separate deployment checks.
//!
//! ## What each body actually contains (post-2026-05-26 fix)
//!
//! Real n8n-importable JSON, not a placeholder:
//!   - `name` — the workflow's own display name (operator sees in
//!     n8n's workflow list).
//!   - `active: false` — operator GO required (AGENTER hard rule).
//!   - A schedule trigger for scheduled starters, a manual trigger for Paperless consult, or an IMAP trigger for email threat review.
//!   - A visible operator configuration node for a reachable NEOTH
//!     origin and an HTTP Request node that uses an operator-bound
//!     HTTP Header Auth credential.
//!   - Deterministic node IDs derived from the slug for stable local
//!     workflow shape. Public workflow POSTs do not deduplicate on node IDs.
//!   - Connections wiring the selected trigger through visible configuration to NEOTH HTTP.
//!
//! Drift-guard tests assert each of these properties per workflow
//! (name match, trigger/cron match, endpoint match, trigger→Configuration→HTTP wiring,
//! credential configuration, slug-derived IDs, **bodies are pairwise distinct
//! across all 10**). See `cfg(test)` block below.
//!
//! ## Why minimal skeletons, not handcrafted production flows
//!
//! Each starter workflow is the smallest honest shape — its documented trigger + NEOTH HTTP
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
//!   1. paperless_invoice_consult — PL-03 — manual local keyword consult
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

fn build_paperless_consult_workflow(name: &str, endpoint: &str, method: &str) -> String {
    let url = format!("={{{{ $json.neothBaseUrl + '{endpoint}' }}}}");
    let body = serde_json::json!({
        "name": name, "active": false,
        "nodes": [
            { "parameters": {}, "id": "paperless_invoice_consult_manual", "name": "Manual Trigger", "type": "n8n-nodes-base.manualTrigger", "typeVersion": 1, "position": [0, 200], "notesInFlow": true, "notes": "Run manually only after entering an actual question in Operator Configuration. This starter has no schedule or document-event trigger." },
            { "parameters": { "mode": "manual", "assignments": { "assignments": [ { "id": "paperless_invoice_consult_neoth_base_url", "name": "neothBaseUrl", "type": "string", "value": NEOTH_HTTP_BASE }, { "id": "paperless_invoice_consult_question", "name": "question", "type": "string", "value": "" }, { "id": "paperless_invoice_consult_limit", "name": "limit", "type": "number", "value": 5 } ] }, "options": {} }, "id": "paperless_invoice_consult_configuration", "name": "Operator Configuration", "type": "n8n-nodes-base.set", "typeVersion": 3.5, "position": [240, 200], "notesInFlow": true, "notes": "Set neothBaseUrl to an address reachable from n8n and enter the actual Paperless question before a manual run. The empty default question is deliberately invalid. Bind an HTTP Header Auth credential with paperless:consult:read on the request node before activation." },
            { "parameters": { "url": url, "method": method, "authentication": "genericCredentialType", "genericAuthType": "httpHeaderAuth", "sendBody": true, "contentType": "json", "specifyBody": "json", "jsonBody": "={{ JSON.stringify({ question: $json.question, limit: $json.limit }) }}", "options": {} }, "id": "paperless_invoice_consult_http", "name": "NEOTH HTTP", "type": "n8n-nodes-base.httpRequest", "typeVersion": 4, "position": [480, 200], "notesInFlow": true, "notes": "Implemented POST /api/paperless/consult requires paperless:consult:read and performs a bounded local Paperless keyword lookup. It does not ingest documents, call Paperless-NGX or a provider, create drafts, or send mail." }
        ],
        "connections": { "Manual Trigger": { "main": [[ { "node": "Operator Configuration", "type": "main", "index": 0 } ]] }, "Operator Configuration": { "main": [[ { "node": "NEOTH HTTP", "type": "main", "index": 0 } ]] } },
        "settings": { "executionOrder": "v1" }
    });
    serde_json::to_string(&body).expect("serde_json::Value always serialises")
}
fn build_email_threat_workflow(name: &str, endpoint: &str, method: &str) -> String {
    let trigger_id = "email_threat_quarantine_imap";
    let configuration_id = "email_threat_quarantine_configuration";
    let retain_id = "email_threat_quarantine_retain_triage_fields";
    let http_id = "email_threat_quarantine_http";
    let url =
        format!("={{{{ $('Operator Configuration').item.json.neothBaseUrl + '{endpoint}' }}}}");

    let body = serde_json::json!({
        "name": name, "active": false,
        "nodes": [
            { "parameters": { "mailbox": "INBOX", "format": "simple", "downloadAttachments": false, "postProcessAction": "nothing", "options": { "trackLastMessageId": true } }, "id": trigger_id, "name": "Email Trigger (IMAP)", "type": "n8n-nodes-base.emailReadImap", "typeVersion": 2.2, "position": [0, 200], "notesInFlow": true, "notes": "Select the IMAP credential in n8n after import; this starter contains no credential data. mailbox is INBOX by default; change this IMAP trigger parameter when a different mailbox is required. downloadAttachments is false, so this is text-only and performs no attachment analysis. postProcessAction: nothing performs no mailbox flag writes. The node UID cursor may advance before the downstream POST; no automatic delivery guarantee is claimed." },
            { "parameters": { "mode": "manual", "includeOtherFields": true, "assignments": { "assignments": [ { "id": "email_threat_quarantine_neoth_base_url", "name": "neothBaseUrl", "type": "string", "value": NEOTH_HTTP_BASE }, { "id": "email_threat_quarantine_source_key", "name": "sourceKey", "type": "string", "value": "work-inbox" } ] }, "options": {} }, "id": configuration_id, "name": "Operator Configuration", "type": "n8n-nodes-base.set", "typeVersion": 3.5, "position": [240, 200], "notesInFlow": true, "notes": "Set neothBaseUrl to an address reachable from the n8n runtime, sourceKey to a stable mailbox/account namespace. Never use an IMAP UID as sourceKey: a UID identifies one message, not a stable mailbox. Bind an HTTP Header Auth credential with Authorization: Bearer <NEOTH n8n API token> on the request node before activation." },
            { "parameters": { "mode": "manual", "includeOtherFields": false, "assignments": { "assignments": [ { "id": "email_threat_quarantine_request_source_key", "name": "source_key", "type": "string", "value": "={{ $json.sourceKey }}" }, { "id": "email_threat_quarantine_request_message_key", "name": "message_key", "type": "string", "value": "={{ typeof $json.metadata?.[\"message-id\"] === 'string' && $json.metadata[\"message-id\"].trim().length > 0 ? $json.metadata[\"message-id\"].trim() : (Number.isSafeInteger($json.attributes?.uid) && $json.attributes.uid > 0 ? 'uid:' + $json.attributes.uid : '') }}" }, { "id": "email_threat_quarantine_request_from", "name": "from", "type": "string", "value": "={{ $json.from || '' }}" }, { "id": "email_threat_quarantine_request_subject", "name": "subject", "type": "string", "value": "={{ $json.subject || '' }}" }, { "id": "email_threat_quarantine_request_body", "name": "body", "type": "string", "value": "={{ $json.textPlain || $json.textHtml || '' }}" }, { "id": "email_threat_quarantine_request_attachment_filenames", "name": "attachment_filenames", "type": "array", "value": "={{ [] }}" } ] }, "options": {} }, "id": retain_id, "name": "Retain Triage Fields", "type": "n8n-nodes-base.set", "typeVersion": 3.5, "position": [480, 200], "notesInFlow": true, "notes": "Retains only the six NEOTH service fields. message_key prefers metadata[message-id], then the message-scoped uid:<UID> fallback; missing both stays empty and NEOTH rejects it. Retrying the same content is safe; operators review failures. No at-least-once or exactly-once delivery claim is made." },
            { "parameters": { "url": url, "method": method, "authentication": "genericCredentialType", "genericAuthType": "httpHeaderAuth", "sendBody": true, "contentType": "json", "specifyBody": "json", "jsonBody": "={{ JSON.stringify({ source_key: $json.source_key, message_key: $json.message_key, from: $json.from, subject: $json.subject, body: $json.body, attachment_filenames: $json.attachment_filenames }) }}", "options": {} }, "id": http_id, "name": "NEOTH HTTP", "type": "n8n-nodes-base.httpRequest", "typeVersion": 4, "position": [720, 200], "notesInFlow": true, "notes": "Implemented POST /api/email/threat/scan requires email:threat:write. It forwards only retained text triage fields; no raw mail object, binary data, credentials, or attachment contents are forwarded. The workflow stays inactive until the operator configures credentials and explicitly enables it." }
        ],
        "connections": {
            "Email Trigger (IMAP)": { "main": [[ { "node": "Operator Configuration", "type": "main", "index": 0 } ]] },
            "Operator Configuration": { "main": [[ { "node": "Retain Triage Fields", "type": "main", "index": 0 } ]] },
            "Retain Triage Fields": { "main": [[ { "node": "NEOTH HTTP", "type": "main", "index": 0 } ]] }
        },
        "settings": { "executionOrder": "v1" }
    });
    serde_json::to_string(&body).expect("serde_json::Value always serialises")
}
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
    if slug == "paperless_invoice_consult" {
        return build_paperless_consult_workflow(name, endpoint, method);
    }
    if slug == "email_threat_quarantine" {
        return build_email_threat_workflow(name, endpoint, method);
    }
    let trigger_id = format!("{slug}_schedule");
    let configuration_id = format!("{slug}_configuration");
    let http_id = format!("{slug}_http");
    let url = format!("={{{{ $json.neothBaseUrl + '{endpoint}' }}}}");
    let unavailable_note = format!(
        "Unavailable starter intent: {endpoint} has no implemented NEOTH n8n API adapter. Keep this workflow inactive until an explicit adapter and its request-payload contract are implemented; no payload adapter is shipped here."
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
    } else if slug == "dream_obsidian_sync" {
        (
            serde_json::json!({
                "url": url,
                "method": method,
                "authentication": "genericCredentialType",
                "genericAuthType": "httpHeaderAuth",
                "sendBody": true,
                "contentType": "json",
                "specifyBody": "json",
                "jsonBody": "={{ JSON.stringify({ day: $now.toUTC().minus({ days: 1 }).toFormat('yyyy-MM-dd') }) }}",
                "options": {}
            }),
            "Implemented POST /api/dreams/obsidian/sync requires dreams:obsidian:write. It syncs the previous UTC archived day only after NEOTH Dream scheduling, vault policy and scheduler-permitted autonomy are configured. Schedule this workflow after the Dream producer; the default trigger is 02:00 UTC. It does not generate Dreams or call a provider. An absent archive can return written:false; response content is not automatically delivered and an empty result carries no delivery guarantee. Inspect the returned durability tag; published_durability_unknown does not confirm disk durability.",
        )
    } else if slug == "reflection_weekly_sync" {
        (
            serde_json::json!({
                "url": url,
                "method": method,
                "authentication": "genericCredentialType",
                "genericAuthType": "httpHeaderAuth",
                "sendBody": true,
                "contentType": "json",
                "specifyBody": "json",
                "jsonBody": "={{ JSON.stringify({ week: $now.toUTC().toFormat(\"kkkk-'W'WW\") }) }}",
                "options": {}
            }),
            "Implemented POST /api/reflections/weekly/obsidian/sync requires reflections:weekly:obsidian:write and a configured Obsidian vault. It exports the current UTC ISO week's existing archive; schedule it after the weekly producer. It does not generate reflections or require Dream scheduling. An absent archive returns written:false. Inspect the durability tag: published_durability_unknown is a publication with unconfirmed disk durability, not rollback or automatic retry permission. No note content is automatically delivered.",
        )
    } else if slug == "calendar_morning_agenda" {
        (
            serde_json::json!({
                "url": url,
                "method": method,
                "authentication": "genericCredentialType",
                "genericAuthType": "httpHeaderAuth",
                "sendBody": true,
                "contentType": "json",
                "specifyBody": "json",
                "jsonBody": "={{ JSON.stringify({ timezone: $json.calendarTimezone, day: $now.setZone($json.calendarTimezone).toFormat('yyyy-MM-dd'), limit: 20 }) }}",
                "options": {}
            }),
            "Implemented POST /api/calendar/agenda requires calendar:read plus a separate account-bound CalDAV read grant in this NEOTH instance (neoth calendar read-access grant). Set calendarTimezone and the workflow schedule timezone before activation. Supports non-recurring UTC/offset timed events and all-day dates; recurring, floating, TZID or malformed events fail explicitly. Returns bounded day events and conflicts with a truncation indicator, without descriptions, attendees or event IDs.",
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
    } else if slug == "paperless_threat_alert" {
        (
            serde_json::json!({
                "url": url, "method": method,
                "authentication": "genericCredentialType", "genericAuthType": "httpHeaderAuth",
                "sendBody": true, "contentType": "json", "specifyBody": "json",
                "jsonBody": "={{ JSON.stringify({ since_unix: Math.floor($now.minus({ minutes: 15 }).toSeconds()), limit: 20 }) }}",
                "options": {}
            }),
            "Implemented POST /api/paperless/findings/recent requires paperless:findings:read and returns recorded_quarantines_only since the explicit 15-minute cutoff. This inactive scheduled read does not alert, deliver, quarantine, or take any automatic action; it does not guarantee full historical coverage or delivery.",
        )
    } else if slug == "consent_audit_export" {
        (
            serde_json::json!({
                "url": url,
                "method": method,
                "authentication": "genericCredentialType",
                "genericAuthType": "httpHeaderAuth",
                "sendBody": true,
                "contentType": "json",
                "specifyBody": "json",
                "jsonBody": "={{ JSON.stringify({ subject: 'local', limit: 50 }) }}",
                "options": {}
            }),
            "Implemented POST /api/permissions/audit requires permissions:read and replays authenticated typed TrustDecision WAL evidence for the explicit subject local. Change subject only to an exact authorised subject identifier. The response contains decision metadata and explicit authenticated-prefix completeness; it does not export raw WAL payloads or secrets.",
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
    let mut body = serde_json::json!({
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
    if slug == "calendar_morning_agenda" {
        body["nodes"][1]["parameters"]["assignments"]["assignments"]
            .as_array_mut()
            .expect("configuration assignments are an array")
            .push(serde_json::json!({
                "id": format!("{slug}_timezone"),
                "name": "calendarTimezone",
                "type": "string",
                "value": "Europe/Berlin"
            }));
        body["settings"]["timezone"] = serde_json::json!("Europe/Berlin");
    } else if matches!(slug, "dream_obsidian_sync" | "reflection_weekly_sync") {
        body["settings"]["timezone"] = serde_json::json!("UTC");
    }
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
        name: "Paperless consult (manual)",
        description: "PL-03 manual bounded local Paperless keyword lookup; enter an actual question before running.",
        cron: "*/5 * * * *",
        endpoint: "/api/paperless/consult",
        method: "POST",
    },
    StarterSpec {
        slug: "email_threat_quarantine",
        name: "Email threat → review queue",
        description: "PL-05 IMAP text-only threat scan into the NEOTH review queue; inactive until configured and enabled.",
        cron: "*/10 * * * *",
        endpoint: "/api/email/threat/scan",
        method: "POST",
    },
    StarterSpec {
        slug: "calendar_morning_agenda",
        name: "Calendar morning agenda",
        description: "Consented CalDAV local-day agenda and conflict summary; configure timezone and a calendar:read credential before activation.",
        cron: "0 8 * * 1-5",
        endpoint: "/api/calendar/agenda",
        method: "POST",
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
        name: "Dream Obsidian sync (previous UTC day)",
        description: "OB-01 nightly sync of the previous UTC archived Dream day; configure Dream and vault policy before activation.",
        cron: "0 2 * * *",
        endpoint: "/api/dreams/obsidian/sync",
        method: "POST",
    },
    StarterSpec {
        slug: "reflection_weekly_sync",
        name: "Reflection weekly sync",
        description: "OB-02 sync of the current UTC ISO week's archived reflections; configure the vault and schedule after the weekly producer before activation.",
        cron: "0 19 * * 0",
        endpoint: "/api/reflections/weekly/obsidian/sync",
        method: "POST",
    },
    StarterSpec {
        slug: "consent_audit_export",
        name: "Typed permission-decision audit export",
        description: "Partial typed permission-decision audit: read authenticated TrustDecision metadata for one explicit subject. This does not export the broader legacy consent audit.",
        cron: "0 20 * * 0",
        endpoint: "/api/permissions/audit",
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
        description: "Read recorded Paperless quarantines from the last 15 minutes; inactive by default and does not send alerts or take action.",
        cron: "*/15 * * * *",
        endpoint: "/api/paperless/findings/recent",
        method: "POST",
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

    /// Scheduled starters embed their cron expression. The IMAP starter is a
    /// trigger-driven exception and must not also schedule scans.
    #[test]
    fn scheduled_starters_embed_cron_while_email_starter_uses_imap_trigger() {
        for (spec, w) in STARTER_SPECS.iter().zip(starter_workflows().iter()) {
            let v: serde_json::Value = serde_json::from_str(w.body).unwrap();
            let nodes = v["nodes"].as_array().expect("nodes is array");
            if spec.slug == "paperless_invoice_consult" {
                assert!(
                    nodes
                        .iter()
                        .any(|n| n["type"] == "n8n-nodes-base.manualTrigger")
                );
                assert!(
                    !nodes
                        .iter()
                        .any(|n| n["type"] == "n8n-nodes-base.scheduleTrigger")
                );
                continue;
            } else if spec.slug == "email_threat_quarantine" {
                assert!(
                    nodes
                        .iter()
                        .any(|n| n["type"] == "n8n-nodes-base.emailReadImap")
                );
                assert!(
                    !nodes
                        .iter()
                        .any(|n| n["type"] == "n8n-nodes-base.scheduleTrigger")
                );
                continue;
            }
            let schedule = nodes
                .iter()
                .find(|n| n["type"] == "n8n-nodes-base.scheduleTrigger")
                .unwrap_or_else(|| {
                    panic!("no scheduleTrigger node in {:?}: {}", spec.slug, w.body)
                });
            let expression = schedule["parameters"]["rule"]["interval"][0]["expression"]
                .as_str()
                .unwrap_or_else(|| panic!("missing cron expression in {:?}", spec.slug));
            assert_eq!(
                expression, spec.cron,
                "body for {:?} has wrong cron",
                spec.slug
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
            let origin = if spec.slug == "email_threat_quarantine" {
                "={{ $('Operator Configuration').item.json.neothBaseUrl + '"
            } else {
                "={{ $json.neothBaseUrl + '"
            };
            let expected = [origin, spec.endpoint, "' }}"].concat();
            assert_eq!(url, expected, "body for {:?} has wrong URL", spec.slug);
            assert_eq!(
                http["parameters"]["method"], spec.method,
                "body for {:?} has wrong HTTP method",
                spec.slug,
            );
        }
    }

    /// Real-skeleton drift guard #4: scheduled starters wire Schedule →
    /// Configuration → NEOTH-HTTP; the IMAP starter retains an explicit
    /// narrowed payload before its request.
    #[test]
    fn each_starter_body_has_its_required_trigger_configuration_and_http_wiring() {
        for w in starter_workflows() {
            let v: serde_json::Value = serde_json::from_str(w.body).unwrap();
            if w.slug == "paperless_invoice_consult" {
                assert_eq!(
                    v["connections"]["Manual Trigger"]["main"][0][0]["node"],
                    "Operator Configuration"
                );
                assert_eq!(
                    v["connections"]["Operator Configuration"]["main"][0][0]["node"],
                    "NEOTH HTTP"
                );
                continue;
            } else if w.slug == "email_threat_quarantine" {
                assert_eq!(
                    v["connections"]["Email Trigger (IMAP)"]["main"][0][0]["node"],
                    "Operator Configuration"
                );
                assert_eq!(
                    v["connections"]["Operator Configuration"]["main"][0][0]["node"],
                    "Retain Triage Fields"
                );
                assert_eq!(
                    v["connections"]["Retain Triage Fields"]["main"][0][0]["node"],
                    "NEOTH HTTP"
                );
                continue;
            }
            assert_eq!(
                v["connections"]["Schedule Trigger"]["main"][0][0]["node"],
                "Operator Configuration"
            );
            assert_eq!(
                v["connections"]["Operator Configuration"]["main"][0][0]["node"],
                "NEOTH HTTP"
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
            } else if w.slug == "dream_obsidian_sync" {
                assert_eq!(http["parameters"]["method"], "POST");
                assert_eq!(http["parameters"]["sendBody"], true);
                assert_eq!(http["parameters"]["contentType"], "json");
                assert_eq!(http["parameters"]["specifyBody"], "json");
                assert_eq!(
                    http["parameters"]["jsonBody"],
                    "={{ JSON.stringify({ day: $now.toUTC().minus({ days: 1 }).toFormat('yyyy-MM-dd') }) }}"
                );
                assert_eq!(v["settings"]["timezone"], "UTC");
                assert!(
                    http["notes"]
                        .as_str()
                        .is_some_and(|notes| notes.contains("requires dreams:obsidian:write")
                            && notes.contains("written:false"))
                );
            } else if w.slug == "reflection_weekly_sync" {
                assert_eq!(http["parameters"]["method"], "POST");
                assert_eq!(http["parameters"]["sendBody"], true);
                assert_eq!(http["parameters"]["contentType"], "json");
                assert_eq!(http["parameters"]["specifyBody"], "json");
                assert_eq!(v["settings"]["timezone"], "UTC");
                assert!(http["notes"].as_str().is_some_and(|notes| {
                    notes.contains("requires reflections:weekly:obsidian:write")
                        && notes.contains("written:false")
                }));
            } else if w.slug == "calendar_morning_agenda" {
                assert_eq!(http["parameters"]["method"], "POST");
                assert_eq!(http["parameters"]["sendBody"], true);
                assert_eq!(http["parameters"]["contentType"], "json");
                assert_eq!(http["parameters"]["specifyBody"], "json");
                assert_eq!(
                    http["parameters"]["jsonBody"],
                    "={{ JSON.stringify({ timezone: $json.calendarTimezone, day: $now.setZone($json.calendarTimezone).toFormat('yyyy-MM-dd'), limit: 20 }) }}",
                );
                assert_eq!(
                    configuration["parameters"]["assignments"]["assignments"][1]["name"],
                    "calendarTimezone",
                );
                assert_eq!(
                    configuration["parameters"]["assignments"]["assignments"][1]["value"],
                    v["settings"]["timezone"],
                );
                assert_eq!(v["active"], false);
                assert!(http["notes"].as_str().is_some_and(|notes| {
                    notes.contains("requires calendar:read")
                        && notes.contains("separate account-bound CalDAV read grant")
                        && notes.contains("fail explicitly")
                }));
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
            } else if w.slug == "paperless_threat_alert" {
                assert_eq!(http["parameters"]["method"], "POST");
                assert_eq!(http["parameters"]["sendBody"], true);
                assert_eq!(http["parameters"]["contentType"], "json");
                assert_eq!(http["parameters"]["specifyBody"], "json");
                assert_eq!(
                    http["parameters"]["jsonBody"],
                    "={{ JSON.stringify({ since_unix: Math.floor($now.minus({ minutes: 15 }).toSeconds()), limit: 20 }) }}"
                );
                assert_eq!(v["active"], false);
                assert!(http["notes"].as_str().is_some_and(|notes| {
                    notes.contains("requires paperless:findings:read")
                        && notes.contains("recorded_quarantines_only")
                        && notes.contains("does not alert")
                }));
            } else if w.slug == "consent_audit_export" {
                assert_eq!(http["parameters"]["method"], "POST");
                assert_eq!(http["parameters"]["sendBody"], true);
                assert_eq!(http["parameters"]["contentType"], "json");
                assert_eq!(http["parameters"]["specifyBody"], "json");
                assert_eq!(
                    http["parameters"]["jsonBody"],
                    "={{ JSON.stringify({ subject: 'local', limit: 50 }) }}"
                );
                assert!(
                    http["notes"].as_str().is_some_and(|notes| {
                        notes.contains("requires permissions:read")
                            && notes.contains("typed TrustDecision")
                            && notes.contains("authenticated-prefix completeness")
                    }),
                    "implemented partial typed permission audit must disclose scope and coverage",
                );
                assert!(
                    w.description
                        .contains("Partial typed permission-decision audit")
                        && w.description.contains("broader legacy consent audit"),
                    "implemented adapter must not claim the broader consent audit",
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
            } else if w.slug == "paperless_invoice_consult" {
                assert_eq!(http["parameters"]["method"], "POST");
                assert_eq!(http["parameters"]["sendBody"], true);
                assert_eq!(http["parameters"]["contentType"], "json");
                assert_eq!(http["parameters"]["specifyBody"], "json");
                assert_eq!(
                    http["parameters"]["jsonBody"],
                    "={{ JSON.stringify({ question: $json.question, limit: $json.limit }) }}"
                );
                assert!(
                    http["notes"]
                        .as_str()
                        .is_some_and(|notes| notes.contains("requires paperless:consult:read"))
                );
            } else if w.slug == "email_threat_quarantine" {
                assert_eq!(http["parameters"]["method"], "POST");
                assert_eq!(http["parameters"]["sendBody"], true);
                assert_eq!(http["parameters"]["contentType"], "json");
                assert_eq!(http["parameters"]["specifyBody"], "json");
                assert!(http["notes"].as_str().is_some_and(|notes| {
                    notes.contains("requires email:threat:write")
                        && notes.contains("no raw mail object")
                }));
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

    #[test]
    fn dream_obsidian_starter_syncs_previous_utc_day_only() {
        let w = find_by_slug("dream_obsidian_sync").expect("dream starter exists");
        let v: serde_json::Value = serde_json::from_str(w.body).unwrap();
        assert_eq!(v["active"], false);
        assert_eq!(v["settings"]["timezone"], "UTC");
        let nodes = v["nodes"].as_array().unwrap();
        let schedule = nodes
            .iter()
            .find(|n| n["type"] == "n8n-nodes-base.scheduleTrigger")
            .unwrap();
        assert_eq!(
            schedule["parameters"]["rule"]["interval"][0]["expression"],
            "0 2 * * *"
        );
        let http = nodes
            .iter()
            .find(|n| n["type"] == "n8n-nodes-base.httpRequest")
            .unwrap();
        assert_eq!(
            http["parameters"]["url"],
            "={{ $json.neothBaseUrl + '/api/dreams/obsidian/sync' }}"
        );
        assert_eq!(
            http["parameters"]["jsonBody"],
            "={{ JSON.stringify({ day: $now.toUTC().minus({ days: 1 }).toFormat('yyyy-MM-dd') }) }}"
        );
        assert!(
            http["notes"]
                .as_str()
                .unwrap()
                .contains("does not generate Dreams")
        );
        assert!(
            http["notes"]
                .as_str()
                .unwrap()
                .contains("response content is not automatically delivered")
        );
    }
    #[test]
    fn reflection_starter_exports_current_utc_iso_week_only() {
        let workflow = find_by_slug("reflection_weekly_sync").unwrap();
        let value: serde_json::Value = serde_json::from_str(workflow.body).unwrap();
        assert_eq!(value["active"], false);
        assert_eq!(value["settings"]["timezone"], "UTC");
        let nodes = value["nodes"].as_array().unwrap();
        let schedule = nodes.iter().find(|node| node["type"] == "n8n-nodes-base.scheduleTrigger").unwrap();
        assert_eq!(schedule["parameters"]["rule"]["interval"][0]["expression"], "0 19 * * 0");
        let http = nodes.iter().find(|node| node["type"] == "n8n-nodes-base.httpRequest").unwrap();
        assert_eq!(http["parameters"]["url"], "={{ $json.neothBaseUrl + '/api/reflections/weekly/obsidian/sync' }}");
        assert_eq!(http["parameters"]["jsonBody"], "={{ JSON.stringify({ week: $now.toUTC().toFormat(\"kkkk-'W'WW\") }) }}");
        assert!(http["notes"].as_str().unwrap().contains("does not generate reflections"));
        assert!(http["notes"].as_str().unwrap().contains("published_durability_unknown"));
        assert!(http.get("retryOnFail").is_none());
    }

    #[test]
    fn paperless_consult_starter_is_manual_question_lookup_only() {
        let w = find_by_slug("paperless_invoice_consult").expect("consult starter exists");
        let v: serde_json::Value = serde_json::from_str(w.body).unwrap();
        assert_eq!(v["active"], false);
        let nodes = v["nodes"].as_array().unwrap();
        assert!(
            nodes
                .iter()
                .any(|n| n["type"] == "n8n-nodes-base.manualTrigger")
        );
        assert!(
            !nodes
                .iter()
                .any(|n| n["type"] == "n8n-nodes-base.scheduleTrigger")
        );
        let configuration = nodes
            .iter()
            .find(|n| n["name"] == "Operator Configuration")
            .unwrap();
        let fields = configuration["parameters"]["assignments"]["assignments"]
            .as_array()
            .unwrap();
        assert_eq!(fields[0]["name"], "neothBaseUrl");
        assert_eq!(fields[1]["name"], "question");
        assert_eq!(fields[1]["value"], "");
        assert_eq!(fields[2]["name"], "limit");
        assert_eq!(fields[2]["value"], 5);
        let http = nodes
            .iter()
            .find(|n| n["type"] == "n8n-nodes-base.httpRequest")
            .unwrap();
        assert_eq!(
            http["parameters"]["url"],
            "={{ $json.neothBaseUrl + '/api/paperless/consult' }}"
        );
        assert_eq!(http["parameters"]["method"], "POST");
        assert_eq!(
            http["parameters"]["authentication"],
            "genericCredentialType"
        );
        assert_eq!(http["parameters"]["genericAuthType"], "httpHeaderAuth");
        assert_eq!(
            http["parameters"]["jsonBody"],
            "={{ JSON.stringify({ question: $json.question, limit: $json.limit }) }}"
        );
        assert!(
            http["notes"]
                .as_str()
                .unwrap()
                .contains("requires paperless:consult:read")
        );
        assert!(
            http["notes"]
                .as_str()
                .unwrap()
                .contains("does not ingest documents")
        );
    }
    #[test]
    fn email_threat_starter_uses_pinned_text_only_imap_contract() {
        let w = find_by_slug("email_threat_quarantine").expect("email starter exists");
        let v: serde_json::Value = serde_json::from_str(w.body).unwrap();
        let nodes = v["nodes"].as_array().unwrap();
        let imap = nodes
            .iter()
            .find(|n| n["type"] == "n8n-nodes-base.emailReadImap")
            .unwrap();
        assert_eq!(imap["typeVersion"], 2.2);
        assert_eq!(imap["parameters"]["mailbox"], "INBOX");
        assert_eq!(imap["parameters"]["format"], "simple");
        assert_eq!(imap["parameters"]["downloadAttachments"], false);
        assert_eq!(imap["parameters"]["postProcessAction"], "nothing");
        assert_eq!(imap["parameters"]["options"]["trackLastMessageId"], true);
        assert!(
            imap.get("credentials").is_none(),
            "credential data must not be exported"
        );

        let configuration = nodes
            .iter()
            .find(|n| n["name"] == "Operator Configuration")
            .unwrap();
        let configured = configuration["parameters"]["assignments"]["assignments"]
            .as_array()
            .unwrap();
        assert_eq!(configured[0]["name"], "neothBaseUrl");
        assert_eq!(configured[1]["name"], "sourceKey");
        assert_eq!(configured[1]["value"], "work-inbox");

        let retain = nodes
            .iter()
            .find(|n| n["name"] == "Retain Triage Fields")
            .unwrap();
        let retained = retain["parameters"]["assignments"]["assignments"]
            .as_array()
            .unwrap();
        let names: Vec<_> = retained
            .iter()
            .map(|field| field["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "source_key",
                "message_key",
                "from",
                "subject",
                "body",
                "attachment_filenames"
            ]
        );
        assert!(
            retained[1]["value"]
                .as_str()
                .unwrap()
                .contains("metadata?.[\"message-id\"]")
        );
        assert!(
            retained[1]["value"]
                .as_str()
                .unwrap()
                .contains("typeof $json.metadata?.[\"message-id\"] === 'string'")
        );
        assert!(
            retained[1]["value"]
                .as_str()
                .unwrap()
                .contains(".trim().length > 0")
        );
        assert!(
            retained[1]["value"]
                .as_str()
                .unwrap()
                .contains("Number.isSafeInteger($json.attributes?.uid)")
        );
        assert!(
            retained[1]["value"]
                .as_str()
                .unwrap()
                .contains("$json.attributes.uid > 0")
        );
        assert!(
            retained[1]["value"]
                .as_str()
                .unwrap()
                .contains("'uid:' + $json.attributes.uid")
        );
        assert_eq!(retained[3]["value"], "={{ $json.subject || '' }}");
        assert_eq!(
            retained[4]["value"],
            "={{ $json.textPlain || $json.textHtml || '' }}"
        );
        assert_eq!(retained[5]["value"], "={{ [] }}");

        let http = nodes
            .iter()
            .find(|n| n["type"] == "n8n-nodes-base.httpRequest")
            .unwrap();
        assert_eq!(
            http["parameters"]["authentication"],
            "genericCredentialType"
        );
        assert_eq!(http["parameters"]["genericAuthType"], "httpHeaderAuth");
        assert_eq!(http["parameters"]["method"], "POST");
        assert_eq!(
            http["parameters"]["url"],
            "={{ $('Operator Configuration').item.json.neothBaseUrl + '/api/email/threat/scan' }}"
        );
        assert_eq!(http["parameters"]["sendBody"], true);
        assert!(
            http["parameters"]["url"]
                .as_str()
                .unwrap()
                .contains("$('Operator Configuration').item.json.neothBaseUrl"),
            "HTTP URL must retain its configuration provenance after Retain Triage Fields strips other fields"
        );
        let json_body = http["parameters"]["jsonBody"].as_str().unwrap();
        for field in [
            "source_key",
            "message_key",
            "from",
            "subject",
            "body",
            "attachment_filenames",
        ] {
            assert!(json_body.contains(field), "request body omits {field}");
        }
        assert!(!json_body.contains("metadata"));
        assert!(!json_body.contains("attributes"));
        assert!(!json_body.contains("textPlain"));
        assert_eq!(v["active"], false);
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
