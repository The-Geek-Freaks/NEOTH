//! N-2 — bootstrap n8n workflow library.
//!
//! Three operator-ready workflows ship in `assets/n8n_workflows/`:
//!   - `daily_summary.json` — evening 21:00 NEOTH activity digest
//!   - `morning_brief.json` — weekday 07:30 motivating brief
//!   - `weekly_stats.json` — Sunday 18:00 stats + archive write
//!
//! Workflows are baked into the binary via `include_str!` so an
//! offline operator can `neoth init` + import bootstrap workflows
//! without downloading anything. The wizard step (deferred to a
//! follow-up) consumes [`BOOTSTRAP_WORKFLOWS`] to render a picker
//! + writes the chosen JSONs into n8n via its REST API.
//!
//! Every workflow ships **inactive** so the operator must
//! explicitly enable it inside the n8n UI after import — matches
//! the AGENTER hard rule "no destructive auto-action without
//! operator GO per command".

/// One bootstrap workflow. `body` is the JSON the wizard POSTs to
/// `<n8n>/api/v1/workflows`; `description` is what the wizard
/// shows in the picker.
#[derive(Clone, Copy, Debug)]
pub struct BootstrapWorkflow {
    pub slug: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub body: &'static str,
}

/// The three operator-ready bootstrap workflows. Adding a fourth
/// needs a JSON asset + an entry here + a test pin for the
/// description length so the wizard picker stays scannable.
pub const BOOTSTRAP_WORKFLOWS: &[BootstrapWorkflow] = &[
    BootstrapWorkflow {
        slug: "daily_summary",
        name: "NEOTH Daily Summary",
        description: "Every evening 21:00 — recall today's activity + send a 5-bullet summary via your preferred channel.",
        body: include_str!("../../assets/n8n_workflows/daily_summary.json"),
    },
    BootstrapWorkflow {
        slug: "morning_brief",
        name: "NEOTH Morning Brief",
        description: "Weekdays 07:30 — open NEOTH threads + a 4-line motivating brief sent to your channel.",
        body: include_str!("../../assets/n8n_workflows/morning_brief.json"),
    },
    BootstrapWorkflow {
        slug: "weekly_stats",
        name: "NEOTH Weekly Stats",
        description: "Sunday 18:00 — week's stats archived to disk + short highlights sent to your channel.",
        body: include_str!("../../assets/n8n_workflows/weekly_stats.json"),
    },
];

/// Look up a bootstrap workflow by slug. Case-sensitive — the
/// wizard CLI surface uses snake_case slugs verbatim.
pub fn find_by_slug(slug: &str) -> Option<&'static BootstrapWorkflow> {
    BOOTSTRAP_WORKFLOWS.iter().find(|w| w.slug == slug)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ships_exactly_three_bootstrap_workflows() {
        // Drift guard — adding a fourth needs an operator picker
        // re-think (3 is "scannable list", 4+ becomes a menu).
        assert_eq!(BOOTSTRAP_WORKFLOWS.len(), 3);
    }

    #[test]
    fn every_workflow_carries_distinct_slug() {
        let slugs: Vec<&str> = BOOTSTRAP_WORKFLOWS.iter().map(|w| w.slug).collect();
        let unique: std::collections::HashSet<_> = slugs.iter().collect();
        assert_eq!(slugs.len(), unique.len(), "duplicate slug");
    }

    #[test]
    fn every_workflow_carries_distinct_name() {
        let names: Vec<&str> = BOOTSTRAP_WORKFLOWS.iter().map(|w| w.name).collect();
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(names.len(), unique.len(), "duplicate name");
    }

    #[test]
    fn every_workflow_body_is_valid_json() {
        for w in BOOTSTRAP_WORKFLOWS {
            let parsed: serde_json::Value = serde_json::from_str(w.body)
                .unwrap_or_else(|e| panic!("{} body invalid JSON: {e}", w.slug));
            assert!(parsed.is_object(), "{} body must be JSON object", w.slug);
        }
    }

    #[test]
    fn every_workflow_body_carries_required_fields() {
        for w in BOOTSTRAP_WORKFLOWS {
            let parsed: serde_json::Value = serde_json::from_str(w.body).unwrap();
            assert!(parsed.get("name").is_some(), "{} missing name", w.slug);
            assert!(parsed.get("nodes").is_some(), "{} missing nodes", w.slug);
            assert!(
                parsed.get("connections").is_some(),
                "{} missing connections",
                w.slug
            );
        }
    }

    #[test]
    fn every_workflow_ships_inactive() {
        // Honour the "no destructive auto-action without operator
        // GO per command" hard rule — bootstrap workflows must be
        // INACTIVE so the operator explicitly enables in the n8n UI.
        for w in BOOTSTRAP_WORKFLOWS {
            let parsed: serde_json::Value = serde_json::from_str(w.body).unwrap();
            let active = parsed.get("active").and_then(|v| v.as_bool());
            assert_eq!(active, Some(false), "{} must ship inactive", w.slug);
        }
    }

    #[test]
    fn every_workflow_tags_itself_as_neoth_bootstrap() {
        // Operator runs `neoth-bootstrap`-tagged workflows through
        // a dedicated review surface; pin the tag.
        for w in BOOTSTRAP_WORKFLOWS {
            let parsed: serde_json::Value = serde_json::from_str(w.body).unwrap();
            let tags = parsed.get("tags").and_then(|v| v.as_array()).unwrap();
            let has_bootstrap = tags.iter().any(|t| {
                t.get("name")
                    .and_then(|n| n.as_str())
                    .map(|s| s == "neoth-bootstrap")
                    .unwrap_or(false)
            });
            assert!(has_bootstrap, "{} missing neoth-bootstrap tag", w.slug);
        }
    }

    #[test]
    fn workflow_descriptions_fit_picker_one_line() {
        // Operator-facing wizard picker renders one line per item.
        // 200 chars is the cap before the line wraps + breaks the
        // picker layout.
        for w in BOOTSTRAP_WORKFLOWS {
            assert!(
                w.description.len() <= 200,
                "{} description too long for picker",
                w.slug
            );
        }
    }

    #[test]
    fn find_by_slug_returns_match() {
        let w = find_by_slug("daily_summary").unwrap();
        assert_eq!(w.name, "NEOTH Daily Summary");
    }

    #[test]
    fn find_by_slug_returns_none_for_unknown() {
        assert!(find_by_slug("nope").is_none());
    }

    #[test]
    fn find_by_slug_is_case_sensitive() {
        assert!(find_by_slug("Daily_Summary").is_none());
        assert!(find_by_slug("daily_summary").is_some());
    }
}
