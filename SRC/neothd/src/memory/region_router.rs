//! M-09 (Session 24) — recall routing per region.
//!
//! Replaces the flat `LIKE %query%` recall path with intent-driven
//! region selection. Operator types "what was that error from
//! Telegram last night" → router classifies → Insula (channels);
//! "what did the council pick" → Cerebellum; "what hit hard this
//! week" → Amygdala (salience overlay). Each query reaches the
//! REGION most likely to hold the answer, drastically narrowing
//! the LIKE-scan vs the prior 0..256 event-type sweep.
//!
//! ## Architecture
//!
//! - [`route_query`] runs a cheap keyword/phrase classifier over
//!   the operator's prompt + returns a [`RouterPlan`] carrying
//!   the **primary region** + an optional **salience boost** (true
//!   when Amygdala should ALSO be consulted alongside the primary).
//! - [`run_routed_recall`] dispatches via
//!   [`crate::memory::regions::recall_from_region`] for each
//!   selected region + merges results. Duplicates by `event_id`
//!   collapse to the highest-importance copy.
//!
//! ## Why keyword-driven and not LLM-driven
//!
//! For v0.4 scope (2.5d) and the AGENTER no-cloud-without-consent
//! rule, routing must run zero-cost + zero-network. Keyword
//! classifier covers the operator's documented common phrasings
//! (German + English). Mis-route surfaces as "0 results" → caller
//! re-asks with explicit `--region` flag (operator-side override
//! ships separately).
//!
//! A future v0.9 enhancement can replace [`route_query`] with a
//! tiny local model — the [`RouterPlan`] interface insulates the
//! consumer from that swap.

use anyhow::Result;
use rusqlite::{Connection, params};
use std::collections::HashMap;

use crate::memory::recall_presentation::{RecallSourceRef, RecallWarmKind};
use crate::memory::regions::{AMYGDALA_THRESHOLD, MemoryRegion, recall_from_region};
use crate::memory::views::EpisodeHit;

/// A local-only routed recall row whose provenance stays attached until the
/// enriched W163 result has passed Stage-3. It is deliberately separate from
/// serialized `EpisodeHit` and the historical routed API.
pub(crate) struct RoutedRecallSourceRow {
    pub(crate) hit: EpisodeHit,
    pub(crate) source: RecallSourceRef,
}

/// Typed warm mapper. The source comes from this exact `idx_consolidated` row;
/// a negative compatibility id is never parsed back into a source reference.
pub(crate) fn recall_warm_like_with_source(
    conn: &Connection,
    query: &str,
    limit: usize,
    min_importance: Option<f64>,
) -> Result<Vec<RoutedRecallSourceRow>> {
    let pattern = format!("%{}%", crate::memory::escape_like(query));
    let sql = if min_importance.is_some() {
        "SELECT id, kind, event_id, consolidated_ts, text, text_hash, importance, access_count \
         FROM idx_consolidated WHERE text COLLATE NOCASE LIKE ?1 ESCAPE '\\' AND importance >= ?2 \
         ORDER BY importance DESC, consolidated_ts DESC LIMIT ?3"
    } else {
        "SELECT id, kind, event_id, consolidated_ts, text, text_hash, importance, access_count \
         FROM idx_consolidated WHERE text COLLATE NOCASE LIKE ?1 ESCAPE '\\' \
         ORDER BY importance DESC, consolidated_ts DESC LIMIT ?2"
    };
    let mut stmt = conn.prepare(sql)?;
    let map_row = |r: &rusqlite::Row<'_>| {
        let consolidated_id: i64 = r.get(0)?;
        let kind: String = r.get(1)?;
        let event_id: Option<i64> = r.get(2)?;
        let source = match (event_id, kind.as_str()) {
            (Some(event_id), "retained") if event_id > 0 => RecallSourceRef::WarmSnapshot {
                consolidated_id,
                kind: RecallWarmKind::Retained,
                original_event_id: Some(event_id),
            },
            (None, "retained") => RecallSourceRef::WarmSnapshot {
                consolidated_id,
                kind: RecallWarmKind::Retained,
                original_event_id: None,
            },
            (None, "summary") => RecallSourceRef::WarmSnapshot {
                consolidated_id,
                kind: RecallWarmKind::Summary,
                original_event_id: None,
            },
            _ => RecallSourceRef::Unavailable,
        };
        Ok(RoutedRecallSourceRow {
            hit: EpisodeHit {
                event_id: event_id.unwrap_or(-consolidated_id),
                event_type: 0,
                ts_ns: r.get(3)?,
                text: r.get(4)?,
                text_hash: r.get(5)?,
                channel: None,
                sender_id: None,
                operator_id: None,
                tier: "warm".to_owned(),
                importance: Some(r.get(6)?),
                access_count: r.get::<_, i64>(7)? as u32,
                trust: 1,
            },
            source,
        })
    };
    let rows = match min_importance {
        Some(minimum) => stmt
            .query_map(params![pattern, minimum, limit as i64], map_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?,
        None => stmt
            .query_map(params![pattern, limit as i64], map_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?,
    };
    Ok(rows)
}

/// What [`route_query`] decides for one prompt. `salience_boost =
/// true` means "ALSO consult Amygdala alongside the primary region"
/// — useful for prompts like "what was the WORST refusal last
/// week" where the operator wants high-importance hits regardless
/// of structural origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterPlan {
    pub primary: MemoryRegion,
    pub salience_boost: bool,
}

impl RouterPlan {
    /// Total set of regions this plan will consult. One or two
    /// depending on `salience_boost`. Used by [`run_routed_recall`]
    /// to drive its merge.
    pub fn regions(&self) -> Vec<MemoryRegion> {
        if self.salience_boost && self.primary != MemoryRegion::Amygdala {
            vec![self.primary, MemoryRegion::Amygdala]
        } else {
            vec![self.primary]
        }
    }
}

/// Keyword set per region. Match order: Amygdala salience boost
/// keywords applied first (orthogonal), then primary-region
/// classification scans Insula → Cerebellum → BasalGanglia →
/// Hypothalamus → Hippocampus (default).
///
/// Keywords are lowercase-matched against the whitespace-tokenized
/// prompt. A single hit per region wins; multi-region tied prompts
/// resolve via the documented scan order (most-specific region
/// first).
struct RegionKeywords {
    region: MemoryRegion,
    keywords: &'static [&'static str],
}

const REGION_KEYWORD_MAP: &[RegionKeywords] = &[
    // Insula — sensory in/out. Channel + sender + message terms.
    RegionKeywords {
        region: MemoryRegion::Insula,
        keywords: &[
            // English
            "channel",
            "message",
            "telegram",
            "discord",
            "slack",
            "whatsapp",
            "keet",
            "inbound",
            "outbound",
            "ingress",
            "egress",
            "webhook",
            "received",
            "sent",
            // German
            "kanal",
            "nachricht",
            "empfangen",
            "gesendet",
            "telegram",
            "eingang",
            "ausgang",
        ],
    },
    // Cerebellum — orchestration: provider / council / kanban / MCP / plugin.
    RegionKeywords {
        region: MemoryRegion::Cerebellum,
        keywords: &[
            // English
            "provider",
            "model",
            "council",
            "kanban",
            "task",
            "agent",
            "subagent",
            "plugin",
            "mcp",
            "tool",
            "response",
            "completion",
            "claude",
            "openai",
            "gemini",
            "code",
            "build",
            "review",
            // German
            "anbieter",
            "modell",
            "antwort",
            "rat",
            "aufgabe",
            "werkzeug",
        ],
    },
    // BasalGanglia — habits + reflexes: cron + hooks.
    RegionKeywords {
        region: MemoryRegion::BasalGanglia,
        keywords: &[
            // English
            "cron",
            "job",
            "scheduled",
            "hook",
            "fired",
            "trigger",
            "reminder",
            "morning",
            "daily",
            "weekly",
            // German
            "zeitplan",
            "stündlich",
            "täglich",
            "wöchentlich",
            "auslöser",
            "erinnerung",
        ],
    },
    // Hypothalamus — drives + self-model: lifecycle / refusal / profile / preset.
    RegionKeywords {
        region: MemoryRegion::Hypothalamus,
        keywords: &[
            // English
            "refusal",
            "refused",
            "boot",
            "shutdown",
            "preset",
            "profile",
            "identity",
            "self",
            "wizard",
            "consent",
            "permission",
            // German
            "verweigerung",
            "verweigert",
            "start",
            "abschluss",
            "vorgabe",
            "profil",
            "identität",
            "selbst",
            "zustimmung",
            "berechtigung",
        ],
    },
    // Hippocampus is the default — no explicit keywords. Anything
    // that doesn't match the above lands here.
];

/// Amygdala salience-boost keywords. When ANY of these appear in
/// the prompt, the router adds Amygdala to the plan regardless of
/// the primary region — "what mattered most" overlays on top of
/// "what kind of event".
const AMYGDALA_BOOST_KEYWORDS: &[&str] = &[
    // English
    "important",
    "critical",
    "urgent",
    "matter",
    "mattered",
    "key",
    "worst",
    "best",
    "biggest",
    "salient",
    // German
    "wichtig",
    "kritisch",
    "dringend",
    "schlimmst",
    "größt",
    "bedeutet",
];

/// Classify the operator's prompt into a [`RouterPlan`]. Pure
/// keyword + lowercase-tokenize. Defaults to Hippocampus when no
/// region keyword matches; layers Amygdala salience boost when a
/// salience term appears regardless of primary.
pub fn route_query(prompt: &str) -> RouterPlan {
    let lowered = prompt.to_lowercase();
    // Salience boost: lexical scan (operator-typed words win even
    // when they appear inside a longer string).
    let salience_boost = AMYGDALA_BOOST_KEYWORDS
        .iter()
        .any(|kw| lowered.contains(kw));

    // Primary classification: first region in REGION_KEYWORD_MAP
    // whose keywords match wins. Order is documented: Insula →
    // Cerebellum → BasalGanglia → Hypothalamus → Hippocampus
    // default.
    for entry in REGION_KEYWORD_MAP.iter() {
        if entry.keywords.iter().any(|kw| lowered.contains(kw)) {
            return RouterPlan {
                primary: entry.region,
                salience_boost,
            };
        }
    }
    RouterPlan {
        primary: MemoryRegion::Hippocampus,
        salience_boost,
    }
}

/// Run the routed recall: dispatch [`recall_from_region`] for each
/// region in the plan, merge results by `event_id` keeping the
/// highest-importance copy, sort by `(importance DESC, ts_ns
/// DESC)`, truncate to `limit`. Returns a vector ready for the
/// operator-facing render.
pub fn run_routed_recall(
    conn: &Connection,
    plan: &RouterPlan,
    query: &str,
    limit: usize,
) -> Result<Vec<EpisodeHit>> {
    // Pull `limit` rows per region so the merge has enough headroom
    // even if duplicates collapse.
    let mut merged: HashMap<i64, EpisodeHit> = HashMap::new();
    for region in plan.regions() {
        let hits = recall_from_region(conn, region, query, limit)?;
        for hit in hits {
            // Collapse duplicates: keep the row whose `importance`
            // is higher. Same row from Amygdala overlay + primary
            // region resolves to one entry.
            let event_id = hit.event_id;
            let keep = match merged.get(&event_id) {
                Some(existing) => {
                    let new_imp = hit.importance.unwrap_or(0.0);
                    let old_imp = existing.importance.unwrap_or(0.0);
                    new_imp > old_imp
                }
                None => true,
            };
            if keep {
                merged.insert(event_id, hit);
            }
        }
    }

    // Sort + truncate.
    let mut out: Vec<EpisodeHit> = merged.into_values().collect();
    out.sort_by(|a, b| {
        let a_imp = a.importance.unwrap_or(0.0);
        let b_imp = b.importance.unwrap_or(0.0);
        b_imp
            .partial_cmp(&a_imp)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.ts_ns.cmp(&a.ts_ns))
    });
    out.truncate(limit);
    Ok(out)
}

/// W163's typed routed result. The legacy router remains hot-only; this helper
/// admits warm rows only where their lack of an event-type binding is honest:
/// the Hippocampus default query, or the Amygdala salience overlay with the
/// same importance threshold. Other primary regions receive no warm row until
/// retained events have a genuine region binding.
pub(crate) fn run_routed_recall_with_source(
    conn: &Connection,
    plan: &RouterPlan,
    query: &str,
    limit: usize,
) -> Result<Vec<RoutedRecallSourceRow>> {
    let mut rows = Vec::new();
    for region in plan.regions() {
        for hit in recall_from_region(conn, region, query, limit)? {
            let source = if hit.event_id > 0 {
                RecallSourceRef::Event {
                    event_id: hit.event_id,
                    event_type: hit.event_type,
                }
            } else {
                RecallSourceRef::Unavailable
            };
            rows.push(RoutedRecallSourceRow { hit, source });
        }
    }

    let warm_minimum = if plan.primary == MemoryRegion::Hippocampus {
        None
    } else if plan.salience_boost {
        Some(AMYGDALA_THRESHOLD)
    } else {
        return Ok(merge_routed_source_rows(rows, limit));
    };
    rows.extend(recall_warm_like_with_source(conn, query, limit, warm_minimum)?);
    Ok(merge_routed_source_rows(rows, limit))
}

fn merge_routed_source_rows(
    rows: impl IntoIterator<Item = RoutedRecallSourceRow>,
    limit: usize,
) -> Vec<RoutedRecallSourceRow> {
    let mut merged: HashMap<i64, RoutedRecallSourceRow> = HashMap::new();
    for row in rows {
        let event_id = row.hit.event_id;
        let keep = match merged.get(&event_id) {
            Some(existing) => row.hit.importance.unwrap_or(0.0) > existing.hit.importance.unwrap_or(0.0),
            None => true,
        };
        if keep {
            merged.insert(event_id, row);
        }
    }
    let mut out: Vec<_> = merged.into_values().collect();
    out.sort_by(|a, b| {
        b.hit
            .importance
            .unwrap_or(0.0)
            .partial_cmp(&a.hit.importance.unwrap_or(0.0))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.hit.ts_ns.cmp(&a.hit.ts_ns))
    });
    out.truncate(limit);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::store;
    use rusqlite::params;

    // ── route_query: classifier behaviour ─────────────────────────────

    #[test]
    fn defaults_to_hippocampus_when_no_keyword_matches() {
        let plan = route_query("just a generic question about my life");
        assert_eq!(plan.primary, MemoryRegion::Hippocampus);
        assert!(!plan.salience_boost);
    }

    #[test]
    fn channel_keywords_route_to_insula() {
        for prompt in [
            "what was the last telegram message",
            "show me the discord channel ingress",
            "was war die letzte nachricht von sam",
        ] {
            let plan = route_query(prompt);
            assert_eq!(plan.primary, MemoryRegion::Insula, "prompt: {prompt:?}");
        }
    }

    #[test]
    fn provider_keywords_route_to_cerebellum() {
        for prompt in [
            "what did claude say about the kanban task",
            "council picked which provider",
            "welche antwort hat das modell gegeben",
        ] {
            let plan = route_query(prompt);
            assert_eq!(plan.primary, MemoryRegion::Cerebellum, "prompt: {prompt:?}");
        }
    }

    #[test]
    fn cron_and_hook_keywords_route_to_basal_ganglia() {
        for prompt in [
            "did the morning cron job fire",
            "what hooks triggered today",
            "tägliche erinnerung um 9",
        ] {
            let plan = route_query(prompt);
            assert_eq!(
                plan.primary,
                MemoryRegion::BasalGanglia,
                "prompt: {prompt:?}"
            );
        }
    }

    #[test]
    fn profile_and_refusal_keywords_route_to_hypothalamus() {
        for prompt in [
            "what refusal happened last week",
            "show my profile preset",
            "welche identität habe ich",
        ] {
            let plan = route_query(prompt);
            assert_eq!(
                plan.primary,
                MemoryRegion::Hypothalamus,
                "prompt: {prompt:?}"
            );
        }
    }

    #[test]
    fn salience_keywords_add_amygdala_boost() {
        let plan = route_query("what was the most important message");
        assert_eq!(
            plan.primary,
            MemoryRegion::Insula,
            "primary still classifies"
        );
        assert!(plan.salience_boost, "Amygdala overlay must be on");
        assert_eq!(plan.regions().len(), 2);
        assert!(plan.regions().contains(&MemoryRegion::Amygdala));
    }

    #[test]
    fn salience_boost_german_phrasing() {
        let plan = route_query("was war die wichtigste antwort vom modell");
        assert_eq!(plan.primary, MemoryRegion::Cerebellum);
        assert!(plan.salience_boost);
    }

    #[test]
    fn salience_boost_alone_without_primary_keyword_defaults_to_hippocampus() {
        // No region keyword, only salience boost → Hippocampus
        // default + Amygdala overlay.
        let plan = route_query("what was the most important thing");
        assert_eq!(plan.primary, MemoryRegion::Hippocampus);
        assert!(plan.salience_boost);
        assert_eq!(plan.regions().len(), 2);
    }

    #[test]
    fn routerplan_regions_dedupes_amygdala_primary() {
        // Defensive edge case: if a future change ever returns
        // Amygdala as primary with salience_boost=true, the
        // regions() helper must not list it twice.
        let plan = RouterPlan {
            primary: MemoryRegion::Amygdala,
            salience_boost: true,
        };
        assert_eq!(plan.regions(), vec![MemoryRegion::Amygdala]);
    }

    // ── run_routed_recall: integration with the regions surface ───────

    fn seed(conn: &Connection, event_id: i64, event_type: u8, text: &str, importance: f64) {
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?3)",
            params![
                event_id,
                event_type as i64,
                event_id,
                text,
                format!("h{event_id}"),
                importance,
            ],
        )
        .unwrap();
    }

    fn open() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let conn = store::open(&dir.path().join("v.db")).unwrap();
        (dir, conn)
    }

    #[test]
    fn typed_warm_mapper_keeps_the_exact_summary_snapshot_and_escapes_wildcards() {
        let (_dir, conn) = open();
        conn.execute(
            "INSERT INTO idx_consolidated \
             (kind, day, event_id, text, text_hash, importance, consolidated_ts, last_access_ts) \
             VALUES ('summary', '2026-09-21', NULL, 'literal 100% retained', 'warm-literal', 0.8, 20, 0)",
            [],
        )
        .unwrap();
        let consolidated_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO idx_consolidated \
             (kind, day, event_id, text, text_hash, importance, consolidated_ts, last_access_ts) \
             VALUES ('summary', '2026-09-22', NULL, 'unrelated plain row', 'warm-other', 0.9, 21, 0)",
            [],
        )
        .unwrap();

        let rows = recall_warm_like_with_source(&conn, "%", 10, None).unwrap();
        assert_eq!(rows.len(), 1, "a wildcard query must be literal");
        assert_eq!(rows[0].hit.event_id, -consolidated_id);
        assert!(matches!(
            &rows[0].source,
            RecallSourceRef::WarmSnapshot {
                consolidated_id: id,
                kind: RecallWarmKind::Summary,
                ..
            } if *id == consolidated_id
        ));
    }

    #[test]
    fn enriched_router_admits_a_warm_summary_only_for_hippocampus_or_salience() {
        let (_dir, conn) = open();
        conn.execute(
            "INSERT INTO idx_consolidated \
             (kind, day, event_id, text, text_hash, importance, consolidated_ts, last_access_ts) \
             VALUES ('summary', '2026-09-21', NULL, 'shared recall phrase', 'warm-summary', 0.90, 20, 0)",
            [],
        )
        .unwrap();
        let summary_id = conn.last_insert_rowid();
        let hippocampus = RouterPlan {
            primary: MemoryRegion::Hippocampus,
            salience_boost: false,
        };
        let rows = run_routed_recall_with_source(&conn, &hippocampus, "shared", 1).unwrap();
        assert_eq!(rows.len(), 1, "selection still honours the routed limit");
        assert!(matches!(
            &rows[0].source,
            RecallSourceRef::WarmSnapshot {
                consolidated_id: id,
                kind: RecallWarmKind::Summary,
                ..
            } if *id == summary_id
        ));

        let insula = RouterPlan {
            primary: MemoryRegion::Insula,
            salience_boost: false,
        };
        assert!(
            run_routed_recall_with_source(&conn, &insula, "shared", 10)
                .unwrap()
                .is_empty(),
            "unbound warm summaries must not leak into a structural region"
        );
    }

    #[test]
    fn typed_warm_mapper_fails_closed_for_an_unknown_snapshot_shape() {
        let (_dir, conn) = open();
        conn.execute(
            "INSERT INTO idx_consolidated \
             (kind, day, event_id, text, text_hash, importance, consolidated_ts, last_access_ts) \
             VALUES ('summary', '2026-09-21', 0, 'unknown warm shape', 'warm-unknown', 0.8, 20, 0)",
            [],
        )
        .unwrap();
        let rows = recall_warm_like_with_source(&conn, "unknown", 10, None).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(matches!(&rows[0].source, RecallSourceRef::Unavailable));
    }

    #[test]
    fn routed_recall_returns_only_matching_primary_region_rows() {
        let (_dir, conn) = open();
        seed(&conn, 1, 0x32, "telegram sam hi", 0.5); // Insula
        seed(&conn, 2, 0x65, "claude provider call", 0.5); // Cerebellum
        seed(&conn, 3, 0x01, "generic note", 0.5); // Hippocampus

        let plan = route_query("show telegram messages");
        assert_eq!(plan.primary, MemoryRegion::Insula);
        let hits = run_routed_recall(&conn, &plan, "sam", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].event_id, 1);
    }

    #[test]
    fn routed_recall_with_salience_boost_merges_primary_and_amygdala() {
        let (_dir, conn) = open();
        // Three Insula rows; two are amygdala-grade.
        seed(&conn, 1, 0x32, "telegram low importance ping", 0.2);
        seed(&conn, 2, 0x32, "telegram critical alert", 0.95);
        seed(&conn, 3, 0x32, "telegram another big issue", 0.90);
        // One Cerebellum row that's amygdala-grade but NOT Insula
        // (would surface ONLY via the Amygdala overlay).
        seed(&conn, 4, 0x65, "council critical decision", 0.95);

        // Prompt: "most important telegram" → Insula primary +
        // Amygdala boost.
        let plan = route_query("show me the most important telegram messages");
        assert_eq!(plan.primary, MemoryRegion::Insula);
        assert!(plan.salience_boost);

        let hits = run_routed_recall(&conn, &plan, "critical", 10).unwrap();
        // Insula primary returns events 2 (the only Insula row
        // matching "critical"); Amygdala overlay adds event 4
        // (Cerebellum 0.95 + LIKE "critical").
        let ids: Vec<i64> = hits.iter().map(|h| h.event_id).collect();
        assert!(ids.contains(&2), "Insula primary must hit: {ids:?}");
        assert!(ids.contains(&4), "Amygdala overlay must add: {ids:?}");
    }

    #[test]
    fn merge_collapses_duplicates_keeping_higher_importance() {
        let (_dir, conn) = open();
        // Insula event with high importance — surfaces via BOTH
        // Insula primary AND Amygdala overlay. The merge must
        // return it ONCE.
        seed(&conn, 1, 0x32, "telegram critical alert", 0.95);

        let plan = RouterPlan {
            primary: MemoryRegion::Insula,
            salience_boost: true,
        };
        let hits = run_routed_recall(&conn, &plan, "telegram", 10).unwrap();
        assert_eq!(hits.len(), 1, "duplicate event_id must collapse to one row");
        assert_eq!(hits[0].event_id, 1);
    }

    #[test]
    fn routed_recall_sorts_merged_results_by_importance_desc_then_ts_desc() {
        let (_dir, conn) = open();
        seed(&conn, 1, 0x32, "telegram low", 0.1);
        seed(&conn, 2, 0x32, "telegram high old", 0.9);
        seed(&conn, 3, 0x32, "telegram high new", 0.9);

        let plan = RouterPlan {
            primary: MemoryRegion::Insula,
            salience_boost: false,
        };
        let hits = run_routed_recall(&conn, &plan, "telegram", 10).unwrap();
        assert_eq!(hits.len(), 3);
        // Sorted importance DESC then ts_ns DESC.
        assert_eq!(hits[0].event_id, 3, "highest-importance newest first");
        assert_eq!(hits[1].event_id, 2, "highest-importance older second");
        assert_eq!(hits[2].event_id, 1, "lowest-importance last");
    }

    #[test]
    fn routed_recall_respects_limit_after_merge() {
        let (_dir, conn) = open();
        for i in 1..=10 {
            seed(&conn, i, 0x32, "telegram msg", 0.5);
        }
        let plan = RouterPlan {
            primary: MemoryRegion::Insula,
            salience_boost: false,
        };
        let hits = run_routed_recall(&conn, &plan, "telegram", 3).unwrap();
        assert_eq!(hits.len(), 3);
    }
}
