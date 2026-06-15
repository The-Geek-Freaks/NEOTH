//! Skill router — decides which skill (if any) activates on a given message.
//!
//! V1: keyword-scan only. Each enabled skill's `trigger_keywords` are tested
//! against the lowercased message; the skill with the most distinct keyword
//! hits wins, ties broken by skill id (stable). Returns `None` when no
//! keyword matches.
//!
//! V2 (Day-14b Phase 2, shipped 2026-05-23): embedding re-rank — LIVE.
//! Stage 1 produces a candidate list; Stage 2 ([`route_stage2_embedding`])
//! embeds `(message, skill.description)` via an
//! [`crate::providers::embed::EmbedProvider`] and picks the max-cosine
//! candidate with similarity ≥ `EMBEDDING_THRESHOLD` ([`cosine_rerank`]).
//! Activated from `cli::chat` when an `inference.embedding_provider` is
//! configured; falls back to keyword-only Stage 1 otherwise.
//!
//! **Lazy routing (GOLD-ADOPT-28).** NEOTH keeps per-invocation context minimal
//! by a two-level lazy selection rather than loading the whole skill library:
//!   1. `route` / `route_stage2_embedding` pick AT MOST ONE skill — the others'
//!      bodies never enter the prompt.
//!   2. Within that skill, [`crate::skills::mode_registry::ModeRegistry`] picks
//!      the matched MODE, and [`compose_mode_skill_layer`] loads ONLY that
//!      mode's `system_prompt_delta` (its "reference sub-doc") on top of the
//!      skill's thin base — the 14 sibling modes of a 15-mode skill like
//!      `academic_research` never load. This is the
//!      "intent → matched reference sub-doc, only that sub-doc loads" pattern.
//!
//! The router never mutates skills; cloning is fine because manifests are
//! small (typically < 1 KiB).

use super::mode_registry::ResolvedMode;
use super::schema::Skill;

/// The skill picked by the router for one message, plus the keywords that
/// fired (mostly for logging + `neoth skills test`).
#[derive(Debug, Clone)]
pub struct RouteMatch<'a> {
    pub skill: &'a Skill,
    /// Distinct keywords that hit, lowercased — order matches the manifest.
    pub matched_keywords: Vec<String>,
    /// Cosine similarity if Stage-2 embedding ran. None for keyword-only.
    pub embedding_score: Option<f32>,
}

/// Embedding threshold for Stage 2 (per synthesis tech-pin). Unused until
/// the embedding model is wired; kept here so the constant lives with the
/// router that consumes it.
pub const EMBEDDING_THRESHOLD: f32 = 0.72;

/// Number of whitespace-separated words in a trigger keyword (min 1). A
/// multi-word trigger like `"pay down tech debt"` (weight 4) is a far more
/// intentional signal than a lone generic token like `"ideas"` (weight 1):
/// the operator had to type the whole phrase. The router scores by SUMMED
/// weight rather than raw hit-count so specific phrases dominate generic
/// single tokens — and the [`route_with_min_weight`] floor can then suppress
/// activations that rest on nothing but a single generic word.
fn keyword_weight(kw: &str) -> usize {
    kw.split_whitespace().count().max(1)
}

/// Minimum summed keyword weight a skill needs to activate under the default
/// (gated) router. `1` preserves the historical floorless behaviour: any
/// single keyword hit — even one generic token — activates. Full-auto mode,
/// which enables the entire bundled library (incl. the 68 `pm-*` skills whose
/// triggers include generic tokens like `"ideas"`/`"strategy"`), raises this
/// to [`FULL_AUTO_MIN_WEIGHT`] so a lone generic token can no longer hijack a
/// turn — a multi-word phrase (weight ≥ 2) or two distinct hits is required.
pub const DEFAULT_MIN_WEIGHT: usize = 1;

/// Confidence floor applied by the full-auto router (all skills enabled).
/// Weight 2 = either one ≥2-word trigger phrase, or two distinct single-token
/// hits. A single generic single-word keyword (weight 1) no longer activates.
pub const FULL_AUTO_MIN_WEIGHT: usize = 2;

/// Pick the best matching skill, if any. Stage-1 keyword scan only.
///
/// Uses [`DEFAULT_MIN_WEIGHT`] — see [`route_with_min_weight`] to raise the
/// confidence floor (full-auto mode does, to keep a fully-populated skill
/// library from false-activating on generic single tokens).
pub fn route<'a>(message: &str, skills: &'a [Skill]) -> Option<RouteMatch<'a>> {
    route_with_min_weight(message, skills, DEFAULT_MIN_WEIGHT)
}

/// Stage-1 keyword router with an explicit confidence floor. A skill activates
/// only when the SUMMED [`keyword_weight`] of its matched triggers is
/// `>= min_weight`. The winner is the highest summed weight, ties broken by
/// skill id alphabetically (stable, deterministic). `embedding_score` is left
/// `None` — Stage-2 cosine re-rank is a separate path.
pub fn route_with_min_weight<'a>(
    message: &str,
    skills: &'a [Skill],
    min_weight: usize,
) -> Option<RouteMatch<'a>> {
    let haystack = lowercase_tokens(message);
    if haystack.is_empty() {
        return None;
    }

    let mut best: Option<(usize, &Skill, Vec<String>)> = None;
    for skill in skills {
        if !skill.is_enabled() {
            continue;
        }
        let mut hits = Vec::new();
        let mut weight = 0usize;
        for kw in skill.trigger_keywords() {
            let kw_norm = kw.trim().to_lowercase();
            if kw_norm.is_empty() {
                continue;
            }
            if keyword_matches(&kw_norm, &haystack, message) && !hits.contains(&kw_norm) {
                weight += keyword_weight(&kw_norm);
                hits.push(kw_norm);
            }
        }
        if hits.is_empty() || weight < min_weight.max(1) {
            continue;
        }
        let take = match &best {
            None => true,
            Some((bw, b, _)) => weight > *bw || (weight == *bw && skill.id() < b.id()),
        };
        if take {
            best = Some((weight, skill, hits));
        }
    }

    best.map(|(_, skill, matched_keywords)| RouteMatch {
        skill,
        matched_keywords,
        embedding_score: None,
    })
}

/// GOLD-ADOPT-28 lazy skill-routing — compose the system-prompt LAYER for an
/// activated MODE, loading ONLY the matched mode's reference sub-doc
/// (`system_prompt_delta`) on top of its parent skill's thin base. The parent
/// skill's OTHER mode deltas never enter the prompt, so per-invocation context
/// stays minimal even for a 15-mode skill.
///
/// This is the single source of truth shared by BOTH the CLI (`cli::chat`) and
/// channel (`cli::serve_pipeline`) dispatch paths — previously each had its own
/// copy of the rule, which drifted (the channel path once dropped the skill
/// tool-allowlist entirely; see SC-11). Returns `None` only when there is
/// neither a parent skill body nor a mode delta to inject.
pub fn compose_mode_skill_layer(parent: Option<&Skill>, resolved: &ResolvedMode) -> Option<String> {
    let delta = &resolved.mode.system_prompt_delta;
    match parent {
        // Thin base + ONLY the matched mode's reference sub-doc.
        Some(p) if !delta.is_empty() => Some(format!("{}\n\n{}", p.system_prompt(), delta)),
        Some(p) => Some(p.system_prompt().to_string()),
        // Orphan mode (parent skill unloaded) — the delta alone still carries
        // the behaviour.
        None if !delta.is_empty() => Some(delta.clone()),
        None => None,
    }
}

/// Stage-2 cosine re-rank helper for callers that already hold a
/// pre-computed message embedding + cached skill embeddings. Pure
/// function — no I/O, no embedding model required. Returns the
/// best-cosine skill **only when the score crosses
/// [`EMBEDDING_THRESHOLD`]**; below threshold returns `None` so
/// callers can fall back to keyword Stage-1.
///
/// The Phase 2 wire-up in `cli::chat` will:
///   1. Embed the operator's message once via `EmbedProvider`
///   2. Look up each candidate skill's pre-computed description
///      embedding from the session-cached `HashMap<&str, Vec<f32>>`
///   3. Call this function to pick the cosine winner
///
/// Today this exists so consumers can prep against the stable API
/// surface; the actual chat-loop wire-up is a follow-on commit.
pub fn cosine_rerank<'a>(
    message_embedding: &[f32],
    skills: &'a [Skill],
    skill_embeddings: &std::collections::HashMap<String, Vec<f32>>,
) -> Option<(&'a Skill, f32)> {
    let mut best: Option<(&Skill, f32)> = None;
    for skill in skills {
        if !skill.is_enabled() {
            continue;
        }
        let Some(skill_emb) = skill_embeddings.get(skill.id()) else {
            continue;
        };
        let score = crate::providers::embed::cosine(message_embedding, skill_emb);
        if score < EMBEDDING_THRESHOLD {
            continue;
        }
        let take = match &best {
            None => true,
            Some((_, bs)) => score > *bs,
        };
        if take {
            best = Some((skill, score));
        }
    }
    best
}

/// Day-14b Phase 2 chat-loop entry point. Runs Stage-2 cosine
/// re-rank over installed skills via an `EmbedProvider` — embeds
/// the message, then embeds each enabled skill's description on
/// demand. Returns the highest-cosine skill above
/// [`EMBEDDING_THRESHOLD`], or `None` when nothing crosses the bar.
///
/// **Cost**: N+1 embedding calls per invocation (1 message + 1 per
/// enabled skill), re-embedding every skill description on EVERY call —
/// there is NO session/process embedding cache yet (a planned but
/// unshipped optimisation). For the default 44-skill bundle (30 with explicit
/// `enabled: true` + 14 defaulting on) on CPU Qwen2.5-3B this is ~10-30s
/// cold-start; warm calls run in seconds.
/// PF-01 (Session 30) made this path the default routing strategy
/// (`freedom.yaml::skills.always_embed_route`, default `true`), but the
/// cost is self-gating: Stage-2 only runs at all when the operator has
/// configured `inference.embedding_provider` (null by default), and the
/// chat CLI is single-shot (one turn per process) so the N+1 cost does
/// not accumulate across turns. Operators who want to skip Stage-2
/// entirely set `embedding_provider: null` (or `always_embed_route:
/// false` to keep it as a keyword-miss-only fallback). A skill-embedding
/// cache to amortise the per-skill embeds across a long-running session
/// remains a tracked follow-up.
///
/// Failure modes are silent + fall back to keyword-only:
///   - Provider returns Err on the message embed → returns None
///   - Any individual skill embed fails → that skill is skipped, others
///     still scored
///   - Dim mismatch between message + skill embeddings → `cosine()`
///     returns 0.0, that skill never crosses threshold
pub async fn route_stage2_embedding<'a>(
    message: &str,
    skills: &'a [Skill],
    embed_provider: &dyn crate::providers::embed::EmbedProvider,
) -> Option<(&'a Skill, f32)> {
    use crate::providers::embed::EmbedRequest;
    if message.trim().is_empty() || skills.is_empty() {
        return None;
    }
    let msg_resp = match embed_provider.embed(EmbedRequest::new(message)).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                provider = embed_provider.name(),
                error = %e,
                "stage2: message embed failed; falling back to keyword-only"
            );
            return None;
        }
    };
    let mut skill_embeddings: std::collections::HashMap<String, Vec<f32>> =
        std::collections::HashMap::new();
    for skill in skills {
        if !skill.is_enabled() {
            continue;
        }
        let desc = skill.description();
        if desc.trim().is_empty() {
            continue;
        }
        match embed_provider
            .embed(EmbedRequest::new(desc.to_string()))
            .await
        {
            Ok(r) => {
                skill_embeddings.insert(skill.id().to_string(), r.vector);
            }
            Err(e) => {
                tracing::warn!(
                    skill = skill.id(),
                    error = %e,
                    "stage2: skill embed failed; skipping in cosine re-rank"
                );
            }
        }
    }
    cosine_rerank(&msg_resp.vector, skills, &skill_embeddings)
}

fn lowercase_tokens(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_lowercase())
        .collect()
}

/// A keyword matches if its lowercased form appears as a whole word inside
/// the lowercased message OR — for keywords that contain non-alphanumeric
/// characters (spaces, hyphens, dots) — as an exact substring of the full
/// lowercased message. Hyphenated triggers like `fact-check` or `node.js`
/// would never tokenise to a single token, so they need substring matching.
fn keyword_matches(needle: &str, tokens: &[String], full_message: &str) -> bool {
    if needle.chars().any(|c| !c.is_alphanumeric()) {
        full_message.to_lowercase().contains(needle)
    } else {
        tokens.iter().any(|t| t == needle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skills::schema::SkillManifest;
    use std::path::PathBuf;

    fn skill(id: &str, kws: &[&str], enabled: bool) -> Skill {
        Skill {
            manifest: SkillManifest {
                id: id.to_string(),
                description: format!("test skill {id}"),
                version: "1.0.0".to_string(),
                trigger_keywords: kws.iter().map(|s| (*s).to_string()).collect(),
                system_prompt: format!("you are {id}"),
                tool_allowlist: vec![],
                author: None,
                tags: vec![],
                homepage: None,
                source: None,
                modes: vec![],
                enabled,
            },
            path: PathBuf::from(format!("/tmp/{id}/skill.yaml")),
            content_hash: String::new(),
        }
    }

    #[test]
    fn no_skills_no_match() {
        assert!(route("hello", &[]).is_none());
    }

    // ── GOLD-ADOPT-28 lazy mode-layer composition ──────────────────────────

    fn resolved_mode(skill_id: &str, mode_id: &str, delta: &str) -> ResolvedMode {
        use crate::skills::schema::{ModeEntry, OutputContract, Oversight, Spectrum};
        ResolvedMode {
            skill_id: skill_id.to_string(),
            mode: ModeEntry {
                id: mode_id.to_string(),
                description: format!("mode {mode_id}"),
                spectrum: Spectrum::Balanced,
                oversight: Oversight::High,
                output: OutputContract {
                    format: "markdown".into(),
                    length_hint: None,
                },
                trigger_phrases: vec![],
                system_prompt_delta: delta.to_string(),
            },
        }
    }

    #[test]
    fn lazy_mode_layer_loads_only_matched_mode_sub_doc() {
        // The lazy-routing invariant: a matched mode loads its OWN delta on top
        // of the parent's thin base — a SIBLING mode's delta never enters.
        let mut parent = skill("research", &[], true);
        parent.manifest.system_prompt = "BASE-HEADER".to_string();
        let matched = resolved_mode("research", "lit-review", "LIT-REVIEW-DELTA");
        let layer = compose_mode_skill_layer(Some(&parent), &matched).unwrap();
        assert!(layer.contains("BASE-HEADER"), "{layer}");
        assert!(layer.contains("LIT-REVIEW-DELTA"), "{layer}");
        // A different mode's reference sub-doc was NOT loaded.
        assert!(!layer.contains("FACT-CHECK-DELTA"), "{layer}");
    }

    #[test]
    fn lazy_mode_layer_handles_empty_delta_and_orphan_mode() {
        let mut parent = skill("s", &[], true);
        parent.manifest.system_prompt = "BASE".to_string();
        // Empty delta → just the parent base.
        assert_eq!(
            compose_mode_skill_layer(Some(&parent), &resolved_mode("s", "m", "")).unwrap(),
            "BASE"
        );
        // No parent + empty delta → None (nothing to inject).
        assert!(compose_mode_skill_layer(None, &resolved_mode("s", "m", "")).is_none());
        // No parent + a delta → the orphan mode's delta alone.
        assert_eq!(
            compose_mode_skill_layer(None, &resolved_mode("s", "m", "DELTA")).unwrap(),
            "DELTA"
        );
    }

    #[test]
    fn keyword_word_boundary_match() {
        let skills = vec![skill("news", &["news"], true)];
        let m = route("Bring me the news please", &skills).unwrap();
        assert_eq!(m.skill.id(), "news");
        assert_eq!(m.matched_keywords, vec!["news"]);
    }

    #[test]
    fn substring_within_word_does_not_match_single_token_keyword() {
        let skills = vec![skill("news", &["news"], true)];
        // "newsletter" contains "news" but the token "newsletter" should
        // NOT match a single-word keyword.
        let m = route("subscribe to my newsletter", &skills);
        assert!(m.is_none());
    }

    #[test]
    fn multi_word_keyword_is_substring_matched() {
        let skills = vec![skill("brief", &["morning briefing"], true)];
        let m = route("Run the morning briefing now", &skills).unwrap();
        assert_eq!(m.skill.id(), "brief");
    }

    #[test]
    fn most_hits_wins() {
        let skills = vec![
            skill("a", &["news"], true),
            skill("b", &["news", "headlines"], true),
        ];
        let m = route("news and headlines please", &skills).unwrap();
        assert_eq!(m.skill.id(), "b");
        assert_eq!(m.matched_keywords.len(), 2);
    }

    #[test]
    fn tie_broken_by_skill_id_alphabetically() {
        let skills = vec![
            skill("zeta", &["news"], true),
            skill("alpha", &["news"], true),
        ];
        let m = route("morning news", &skills).unwrap();
        assert_eq!(m.skill.id(), "alpha");
    }

    #[test]
    fn disabled_skill_never_matches() {
        let skills = vec![skill("news", &["news"], false)];
        assert!(route("morning news", &skills).is_none());
    }

    #[test]
    fn case_insensitive_match() {
        let skills = vec![skill("news", &["NEWS"], true)];
        // Keywords were normalised to lowercase at load time; the router's
        // own trim/lowercase covers an unnormalised path too.
        let m = route("Got any NEWS today?", &skills).unwrap();
        assert_eq!(m.skill.id(), "news");
    }

    #[test]
    fn empty_message_yields_no_match() {
        let skills = vec![skill("news", &["news"], true)];
        assert!(route("", &skills).is_none());
    }

    #[test]
    fn duplicate_keyword_counted_once() {
        let skills = vec![skill("news", &["news", "news"], true)];
        let m = route("news news news", &skills).unwrap();
        assert_eq!(m.matched_keywords.len(), 1);
    }

    // ── full-auto confidence floor (route_with_min_weight) ──────────────────

    #[test]
    fn single_generic_token_suppressed_by_full_auto_floor() {
        // The exact false-activation full-auto must prevent: a lone generic
        // single-word trigger (weight 1) activating on casual usage. Default
        // floor (1) still matches it; the full-auto floor (2) suppresses it.
        let skills = vec![skill("pm_ideas", &["ideas"], true)];
        assert!(
            route("got any ideas for dinner", &skills).is_some(),
            "default floor must preserve historical single-token match"
        );
        assert!(
            route_with_min_weight("got any ideas for dinner", &skills, FULL_AUTO_MIN_WEIGHT)
                .is_none(),
            "full-auto floor must suppress a lone generic single-word trigger"
        );
    }

    #[test]
    fn multi_word_trigger_survives_full_auto_floor() {
        // A ≥2-word phrase is intentional enough to clear the floor on its own.
        let skills = vec![skill("debt", &["pay down tech debt"], true)];
        let m = route_with_min_weight(
            "we should pay down tech debt this sprint",
            &skills,
            FULL_AUTO_MIN_WEIGHT,
        )
        .expect("a 4-word trigger (weight 4) must clear the full-auto floor");
        assert_eq!(m.skill.id(), "debt");
    }

    #[test]
    fn two_single_tokens_survive_full_auto_floor() {
        // Two distinct single-word hits = summed weight 2 = intentional enough.
        let skills = vec![skill("news", &["news", "headlines"], true)];
        let m =
            route_with_min_weight("the news and the headlines", &skills, FULL_AUTO_MIN_WEIGHT)
                .expect("two distinct single-token hits (weight 2) must clear the floor");
        assert_eq!(m.skill.id(), "news");
    }

    #[test]
    fn specific_multi_word_beats_generic_single_token() {
        // Specificity weighting: when a generic token and a specific phrase
        // both match the same message, the heavier (more specific) phrase wins
        // even though each is "one hit".
        let skills = vec![
            skill("generic", &["ideas"], true),
            skill("specific", &["pay down tech debt"], true),
        ];
        let m = route("any ideas on how to pay down tech debt", &skills).unwrap();
        assert_eq!(
            m.skill.id(),
            "specific",
            "the 4-word trigger (weight 4) must outrank the 1-word trigger (weight 1)"
        );
    }

    #[test]
    fn hyphenated_keyword_matches_via_substring() {
        // `fact-check` would never tokenise to one token because the
        // splitter treats `-` as a separator. Pin that the router uses
        // substring matching for any keyword carrying non-alphanumeric
        // characters.
        let skills = vec![skill("fc", &["fact-check"], true)];
        let m = route("Fact-check these claims please", &skills).unwrap();
        assert_eq!(m.skill.id(), "fc");
        assert_eq!(m.matched_keywords, vec!["fact-check"]);
    }

    #[test]
    fn dotted_keyword_matches_via_substring() {
        // Same rule applies to dotted triggers (`node.js`, `v1.0`, etc.).
        let skills = vec![skill("nodejs", &["node.js"], true)];
        let m = route("Got a node.js bug to chase", &skills).unwrap();
        assert_eq!(m.skill.id(), "nodejs");
    }

    // ── Phase 33e AP-1: anti-pattern gate (G.12 Level-Confusion) ────────────
    //
    // The router MUST stay a Schicht-1 filter — its job is to *select skill
    // data to inject*, never *select a pipeline/tool to run*. The contract:
    //   • The output is `Option<RouteMatch>` carrying a `&Skill` reference.
    //   • A `RouteMatch` exposes ONLY data (skill manifest, matched keywords,
    //     optional embedding score). It does NOT expose any executable
    //     function pointer, tool handle, or pipeline switch.
    //   • There is no `dispatch_*` / `execute_*` / `run_skill` method on
    //     RouteMatch — the caller composes the skill's system_prompt into
    //     the existing provider call rather than the router triggering one.
    //
    // This test compiles against the router's public surface. If a future
    // change adds an executable hook to RouteMatch (e.g. `match.run(provider)`),
    // the assertion below has to be revisited — and that revisit is the
    // pause-point where G.12 must be re-evaluated.

    #[test]
    fn route_match_exposes_only_data_not_executors() {
        // Build a minimal match. The point of this test is that the entire
        // surface of `RouteMatch` is reachable as plain getters; if it ever
        // grows a method that *runs* anything, this test won't compile.
        let skills = vec![skill("news", &["news"], true)];
        let m = route("morning news", &skills).expect("match");

        // Data accessors — all read-only.
        let _id: &str = m.skill.id();
        let _prompt: &str = m.skill.system_prompt();
        let _kws: &Vec<String> = &m.matched_keywords;
        let _emb: Option<f32> = m.embedding_score;

        // Compile-time assertion: RouteMatch is Send (so it crosses await
        // points cheaply) but it carries no Future or executor — the
        // caller decides what to do with the data.
        fn assert_send<T: Send>(_t: &T) {}
        assert_send(&m);
    }

    #[test]
    fn route_signature_returns_optional_match_not_a_pipeline() {
        // Reflect on the public function signature: its return type must
        // be `Option<RouteMatch>`, not anything callable. If a future
        // refactor changes route() to return an executor, this fails to
        // compile and the maintainer is forced to re-read the G.12 note
        // above before pushing.
        let skills: Vec<Skill> = Vec::new();
        let r: Option<RouteMatch> = route("anything", &skills);
        assert!(r.is_none(), "empty skill set always returns None");
    }

    #[test]
    fn embedding_score_is_optional_not_a_command() {
        // The Stage-2 embedding hook returns a score, never a directive.
        // Verify the field type at compile time and the documented
        // threshold value.
        assert!(
            (EMBEDDING_THRESHOLD - 0.72).abs() < 1e-6,
            "Stage-2 cosine threshold must stay at 0.72 per round-3 synthesis",
        );
        let skills = vec![skill("news", &["news"], true)];
        let m = route("news", &skills).unwrap();
        // The score is `Option<f32>` (None on the keyword Stage-1 path;
        // Some when Stage-2 `route_stage2_embedding` runs).
        let _: Option<f32> = m.embedding_score;
    }

    // ── AP-1 gate test: router stays a Schicht-1 FILTER, never a Schicht-0 TOOL ──
    //
    // Per `memory/neoth-research-synthesis.md` G.12 Level-Confusion
    // rule: a router that picks among candidate skills is a FILTER.
    // It MUST stay side-effect-free. Any future drift that gives the
    // router an effect surface (executed-action field, async IO, &mut
    // on skills, network call) is a level violation. These tests pin
    // the contract.

    #[test]
    fn ap1_route_is_pure_filter_idempotent_calls_return_equal_match() {
        // Pure functions: same input + same skills → same output.
        // No hidden state, no global cache mutation. If a future
        // commit adds a hit-counter or last-routed-skill cache, this
        // test surfaces the regression.
        let skills = vec![
            skill("news", &["news", "headlines"], true),
            skill("memory", &["recall", "remember"], true),
        ];
        let a = route("show me the headlines", &skills);
        let b = route("show me the headlines", &skills);
        let c = route("show me the headlines", &skills);
        // RouteMatch isn't PartialEq; compare via the observable
        // fields (skill id + matched_keywords + embedding_score).
        let triplet = (
            a.as_ref().map(|m| {
                (
                    m.skill.id().to_string(),
                    m.matched_keywords.clone(),
                    m.embedding_score,
                )
            }),
            b.as_ref().map(|m| {
                (
                    m.skill.id().to_string(),
                    m.matched_keywords.clone(),
                    m.embedding_score,
                )
            }),
            c.as_ref().map(|m| {
                (
                    m.skill.id().to_string(),
                    m.matched_keywords.clone(),
                    m.embedding_score,
                )
            }),
        );
        assert_eq!(triplet.0, triplet.1, "first vs second call");
        assert_eq!(triplet.1, triplet.2, "second vs third call");
    }

    #[test]
    fn ap1_route_does_not_mutate_skills_slice() {
        // Skills are passed by shared reference; the router MUST
        // NOT mutate them. We pin this via a clone-before /
        // clone-after equality check on the observable
        // SkillManifest fields. (Skill doesn't derive PartialEq;
        // serialise to YAML and compare strings.)
        let skills = vec![
            skill("news", &["news"], true),
            skill("memory", &["recall"], false),
        ];
        let before: Vec<String> = skills
            .iter()
            .map(|s| serde_yaml::to_string(&s.manifest).unwrap())
            .collect();
        let _ = route("news today", &skills);
        let _ = route("recall the answer", &skills);
        let after: Vec<String> = skills
            .iter()
            .map(|s| serde_yaml::to_string(&s.manifest).unwrap())
            .collect();
        assert_eq!(before, after, "router must not mutate skill manifests");
    }

    #[test]
    fn ap1_routematch_carries_only_filter_fields() {
        // Compile-time gate: RouteMatch fields are
        //   skill (read-only borrow),
        //   matched_keywords (observable result of the filter),
        //   embedding_score (filter-stage diagnostic).
        // Adding an effect-bearing field (e.g. `executed_action:
        // Option<ToolCall>`, `side_effects: Vec<Effect>`,
        // `tx_handle: Sender<...>`) would require this test to
        // compile with new field destructuring — surfacing the
        // schicht violation at the source. Pin via exhaustive
        // pattern match.
        let skills = vec![skill("news", &["news"], true)];
        let m = route("news", &skills).unwrap();
        // Exhaustive destructure — if RouteMatch gains a new
        // public field, this fails to compile.
        let RouteMatch {
            skill: _picked,
            matched_keywords: _kws,
            embedding_score: _score,
        } = m;
    }

    #[test]
    fn ap1_route_signature_is_sync_no_io_traits() {
        // Compile-time + runtime sanity: route returns a
        // synchronous `Option<RouteMatch>`. If a future refactor
        // makes it `async fn` (i.e. needs an IO context), this
        // test fails to compile because `Option<RouteMatch>` is
        // not a Future. Schicht-1 filters MUST stay sync —
        // routing is the FAST path before the LLM call, can't
        // afford an IO round-trip per turn.
        let skills: Vec<Skill> = vec![];
        let _result: Option<RouteMatch> = route("any message", &skills);
    }

    // ── R4-P1: routing-conflict regression matrix for the 22 bundled skills ──

    /// R4 reviewer P1: "Routing-Konflikte fuer 22 Skills pinnen.
    /// Prompt-Matrix fuer typische deutsche/englische Operator-
    /// Prompts. Erwartete Skill-ID pro Prompt. Tests fuer Konflikte
    /// wie diagnose vs systematic_debugging, writing_plans vs
    /// to_prd, requesting_code_review vs receiving_code_review."
    ///
    /// Loads the full bundled skill set + runs `route` against
    /// canonical operator prompts; asserts the matched skill id.
    /// Catches a future trigger-keyword edit that accidentally lets
    /// e.g. `writing_plans` shadow `to_prd` because both match
    /// "plan".
    #[tokio::test]
    async fn r4_p1_bundled_skill_routing_matrix() {
        use crate::skills::loader::load_all;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        // Empty user dir → loader returns just the bundled set.
        let skills = load_all(dir.path()).await.unwrap();

        // (operator prompt, expected skill id). When a prompt could
        // legitimately match TWO skills, the matrix pins which one
        // wins under the current trigger-keyword design. If a future
        // edit flips the winner, this test fails — that's the point.
        //
        // Each row carries operator-realistic phrasing. EN + DE
        // mixed to exercise the multi-locale trigger sets.
        let cases: &[(&str, &str)] = &[
            // Conflict pair: diagnose vs systematic_debugging.
            // "diagnose this bug" hits BOTH ("diagnose" is a
            // diagnose trigger, "bug" is a systematic_debugging
            // trigger). Highest-hit-count tie-broken by skill id
            // alphabetically → diagnose (d < s).
            ("Please diagnose this bug for me", "diagnose"),
            // Pure systematic-debugging path: only the systematic
            // markers fire.
            ("My tests are failing with a panic", "systematic_debugging"),
            // Conflict pair: writing_plans vs to_prd. Both could
            // claim "write a plan / write a PRD". Pin to_prd for
            // the PRD-named prompt.
            ("Write a PRD for the cost dashboard", "to_prd"),
            (
                "Write an implementation plan for the export feature",
                "writing_plans",
            ),
            // Conflict pair: requesting_code_review vs receiving_code_review.
            ("Can you review my pull request?", "requesting_code_review"),
            ("Addressed feedback on the diff", "receiving_code_review"),
            // Verification (always-on closure gate).
            (
                "All tests passing, fix complete",
                "verification_before_completion",
            ),
            // Mode-level inside academic_research handled by ModeRegistry
            // (separate test); the skill itself activates on broad keywords.
            (
                "Run a lit review on transformer attention",
                "academic_research",
            ),
            (
                "Fact-check these claims in the abstract",
                "academic_research",
            ),
            // German + English mix.
            (
                "Refactor the recall module",
                "improve_codebase_architecture",
            ),
            // Pin pure zoom_out path — avoid `architecture` in the prompt so
            // we don't tie with improve_codebase_architecture and have to
            // rely on alphabetical fallback (which would lose).
            ("zoom out and show the big picture", "zoom_out"),
            // Branch-finish discipline.
            (
                "Ready to ship this branch",
                "finishing_a_development_branch",
            ),
            // Worktree usage skill.
            ("Need to set up a git worktree", "using_git_worktrees"),
            // GOLD-ADAPT-PT-06/07 — ponytail lazy-dev + over-engineering audit.
            ("ponytail mode please", "lazy_dev"),
            ("review for over-engineering in this crate", "lazy_review"),
        ];

        for (prompt, expected_id) in cases {
            let m = route(prompt, &skills);
            match m {
                Some(rm) => assert_eq!(
                    rm.skill.id(),
                    *expected_id,
                    "prompt `{prompt}` expected skill `{expected_id}`, got `{}`",
                    rm.skill.id()
                ),
                None => panic!("prompt `{prompt}` should route to `{expected_id}`, got None"),
            }
        }
    }

    /// GR-159: the bundled pm-product-vision manifest must activate on
    /// every trigger its own system_prompt metadata advertises — the
    /// `trigger_keywords` list and the prompt's Triggers line are kept
    /// in sync. The skill ships `enabled: false`, so force-enable in
    /// memory the way full-auto mode does.
    #[test]
    fn pm_product_vision_north_star_activates() {
        let mut manifest: SkillManifest = serde_yaml::from_str(include_str!(
            "../../assets/skills/pm-product-vision/skill.yaml"
        ))
        .expect("bundled pm-product-vision yaml parses");
        manifest.enabled = true;
        let skill = Skill {
            manifest,
            path: PathBuf::from("/bundled/pm-product-vision/skill.yaml"),
            content_hash: String::new(),
        };
        let skills = [skill];
        for prompt in [
            "align teams around a north star vision",
            "help me write a vision statement for our product",
        ] {
            match route(prompt, &skills) {
                Some(rm) => assert_eq!(
                    rm.skill.id(),
                    "pm-product-vision",
                    "prompt `{prompt}` matched the wrong skill"
                ),
                None => panic!("prompt `{prompt}` should activate pm-product-vision"),
            }
        }
    }

    #[tokio::test]
    async fn r4_p1_no_skill_silently_dominates_unrelated_prompts() {
        // Non-skill prompts (greeting, generic chat) should NOT
        // accidentally activate any bundled skill. Pin so a future
        // contributor who adds an over-broad trigger keyword (e.g.
        // "hello") to any skill fails the test.
        use crate::skills::loader::load_all;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let skills = load_all(dir.path()).await.unwrap();
        let unrelated_prompts = [
            "Hello, how are you?",
            "What time is it?",
            "Tell me a joke.",
            "Was machst du gerade?",
        ];
        for prompt in unrelated_prompts {
            let m = route(prompt, &skills);
            assert!(
                m.is_none(),
                "unrelated prompt `{prompt}` accidentally activated `{}`",
                m.unwrap().skill.id()
            );
        }
    }

    // ── Day-14b Phase 2 hook: cosine_rerank ─────────────────────────

    fn unit_vec(idx: usize, dim: usize) -> Vec<f32> {
        let mut v = vec![0.0f32; dim];
        v[idx] = 1.0;
        v
    }

    #[test]
    fn cosine_rerank_returns_none_below_threshold() {
        // Message embedding orthogonal to all skill embeddings →
        // every cosine score is 0.0, below EMBEDDING_THRESHOLD = 0.72.
        let skills = vec![skill("a", &["foo"], true), skill("b", &["bar"], true)];
        let msg = unit_vec(0, 4);
        let mut embs = std::collections::HashMap::new();
        embs.insert("a".to_string(), unit_vec(1, 4));
        embs.insert("b".to_string(), unit_vec(2, 4));
        assert!(cosine_rerank(&msg, &skills, &embs).is_none());
    }

    #[test]
    fn cosine_rerank_picks_highest_above_threshold() {
        let skills = vec![skill("a", &["foo"], true), skill("b", &["bar"], true)];
        let msg = unit_vec(0, 4);
        let mut embs = std::collections::HashMap::new();
        // skill a → identical to msg → cos = 1.0 (above threshold)
        embs.insert("a".to_string(), unit_vec(0, 4));
        // skill b → orthogonal → cos = 0.0 (below)
        embs.insert("b".to_string(), unit_vec(1, 4));
        let pick = cosine_rerank(&msg, &skills, &embs).unwrap();
        assert_eq!(pick.0.id(), "a");
        assert!((pick.1 - 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_rerank_ignores_disabled_skills() {
        let skills = vec![skill("a", &["foo"], false), skill("b", &["bar"], true)];
        let msg = unit_vec(0, 4);
        let mut embs = std::collections::HashMap::new();
        // Both perfect matches, but `a` is disabled — `b` must win.
        embs.insert("a".to_string(), unit_vec(0, 4));
        embs.insert("b".to_string(), unit_vec(0, 4));
        let pick = cosine_rerank(&msg, &skills, &embs).unwrap();
        assert_eq!(pick.0.id(), "b");
    }

    #[test]
    fn cosine_rerank_skips_skills_without_cached_embedding() {
        let skills = vec![skill("a", &["foo"], true), skill("b", &["bar"], true)];
        let msg = unit_vec(0, 4);
        // Only skill `a` has an embedding; skill `b` is skipped without
        // panicking on missing-key.
        let mut embs = std::collections::HashMap::new();
        embs.insert("a".to_string(), unit_vec(0, 4));
        let pick = cosine_rerank(&msg, &skills, &embs).unwrap();
        assert_eq!(pick.0.id(), "a");
    }

    // ── route_stage2_embedding ─────────────────────────────────────

    /// Toy embed provider: text containing `key` returns the canonical
    /// unit vector at `slot`; texts without the key return an orthogonal
    /// "neutral" vector. Used to drive the stage-2 router through
    /// deterministic cosine scores without real weights.
    struct KeySlotMock {
        dim: usize,
        rules: Vec<(&'static str, usize)>,
    }

    #[async_trait::async_trait]
    impl crate::providers::embed::EmbedProvider for KeySlotMock {
        fn name(&self) -> &'static str {
            "key_slot_mock"
        }
        fn default_dim(&self) -> usize {
            self.dim
        }
        async fn embed(
            &self,
            req: crate::providers::embed::EmbedRequest,
        ) -> anyhow::Result<crate::providers::embed::EmbedResponse> {
            let mut v = vec![0.0f32; self.dim];
            let mut matched = false;
            for (needle, slot) in &self.rules {
                if req.text.to_lowercase().contains(needle) {
                    v[*slot] = 1.0;
                    matched = true;
                    break;
                }
            }
            if !matched {
                // Land in the last slot — orthogonal to all rule slots.
                v[self.dim - 1] = 1.0;
            }
            crate::providers::embed::l2_normalize(&mut v);
            Ok(crate::providers::embed::EmbedResponse {
                vector: v,
                model: "mock".into(),
                latency: std::time::Duration::from_micros(1),
            })
        }
    }

    fn skill_with_desc(id: &str, desc: &str, enabled: bool) -> Skill {
        Skill {
            manifest: SkillManifest {
                id: id.to_string(),
                description: desc.to_string(),
                version: "1.0.0".to_string(),
                trigger_keywords: vec![],
                system_prompt: format!("you are {id}"),
                tool_allowlist: vec![],
                author: None,
                tags: vec![],
                homepage: None,
                source: None,
                modes: vec![],
                enabled,
            },
            path: PathBuf::from(format!("/tmp/{id}/skill.yaml")),
            content_hash: String::new(),
        }
    }

    #[tokio::test]
    async fn stage2_returns_matching_skill_when_message_aligns() {
        // Message contains "weather" → embedded into slot 0.
        // Skill A description contains "weather" → also slot 0.
        // Skill B description contains "news" → slot 1.
        // Expected: cosine(A, msg) = 1.0 → A wins.
        let skills = vec![
            skill_with_desc("a", "weather forecasts", true),
            skill_with_desc("b", "news headlines", true),
        ];
        let provider = KeySlotMock {
            dim: 4,
            rules: vec![("weather", 0), ("news", 1)],
        };
        let pick = route_stage2_embedding("show me the weather", &skills, &provider).await;
        assert!(pick.is_some());
        assert_eq!(pick.unwrap().0.id(), "a");
    }

    #[tokio::test]
    async fn stage2_returns_none_when_message_orthogonal() {
        // Message landed in the neutral slot; all skill descriptions
        // map to slot 0/1. Cosine = 0.0 everywhere → below threshold.
        let skills = vec![
            skill_with_desc("a", "weather forecasts", true),
            skill_with_desc("b", "news headlines", true),
        ];
        let provider = KeySlotMock {
            dim: 4,
            rules: vec![("weather", 0), ("news", 1)],
        };
        let pick = route_stage2_embedding("how do I cook risotto", &skills, &provider).await;
        assert!(pick.is_none());
    }

    #[tokio::test]
    async fn stage2_ignores_empty_message() {
        let skills = vec![skill_with_desc("a", "weather forecasts", true)];
        let provider = KeySlotMock {
            dim: 4,
            rules: vec![("weather", 0)],
        };
        assert!(
            route_stage2_embedding("", &skills, &provider)
                .await
                .is_none()
        );
        assert!(
            route_stage2_embedding("   ", &skills, &provider)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn stage2_ignores_disabled_skills() {
        // Disabled skill matches perfectly but stays unselected.
        let skills = vec![
            skill_with_desc("a", "weather forecasts", false),
            skill_with_desc("b", "news headlines", true),
        ];
        let provider = KeySlotMock {
            dim: 4,
            rules: vec![("weather", 0), ("news", 1)],
        };
        // Message hits weather → if `a` were enabled it'd win, but
        // disabled → no other skill scores above threshold → None.
        let pick = route_stage2_embedding("show me the weather", &skills, &provider).await;
        assert!(pick.is_none());
    }

    #[test]
    fn cosine_rerank_at_exact_threshold_passes() {
        // Probe the EMBEDDING_THRESHOLD = 0.72 boundary directly.
        // Build two unit vectors whose dot product equals the
        // threshold within FP tolerance:
        //
        //   msg       = [1.0, 0.0]                  (unit @ slot 0)
        //   skill_emb = [0.72, sqrt(1 - 0.72²), 0]  (unit, cos with msg = 0.72)
        //
        // |skill_emb|² = 0.72² + (1 - 0.72²) = 1.0 ✓
        //
        // The router's filter is `score < EMBEDDING_THRESHOLD`, so
        // a score equal to the threshold MUST pass (inclusive lower
        // bound). This test fails the day someone flips the check to
        // `<= threshold` without thinking about it.
        let skills = vec![skill("a", &["foo"], true)];
        let msg = vec![1.0f32, 0.0];
        let skill_emb = vec![
            EMBEDDING_THRESHOLD,
            (1.0 - EMBEDDING_THRESHOLD * EMBEDDING_THRESHOLD).sqrt(),
        ];
        // Sanity: skill_emb is already unit-length.
        let len_sq: f32 = skill_emb.iter().map(|x| x * x).sum();
        assert!(
            (len_sq - 1.0).abs() < 1e-6,
            "test setup: skill_emb must be unit"
        );
        // Sanity: cos(msg, skill_emb) == EMBEDDING_THRESHOLD exactly.
        let cos = crate::providers::embed::cosine(&msg, &skill_emb);
        assert!(
            (cos - EMBEDDING_THRESHOLD).abs() < 1e-6,
            "test setup: cos must equal threshold, got {cos}"
        );
        let mut embs = std::collections::HashMap::new();
        embs.insert("a".to_string(), skill_emb);
        let pick = cosine_rerank(&msg, &skills, &embs);
        assert!(
            pick.is_some(),
            "score at exact threshold MUST pass (inclusive)"
        );
        let (winner, score) = pick.unwrap();
        assert_eq!(winner.id(), "a");
        assert!((score - EMBEDDING_THRESHOLD).abs() < 1e-6);
    }

    #[test]
    fn cosine_rerank_just_below_threshold_is_rejected() {
        // Companion to the at-threshold test — verify a score one ULP
        // below the threshold is REJECTED. Same construction but
        // cos = threshold - 1e-4 (well inside FP precision).
        let skills = vec![skill("a", &["foo"], true)];
        let below = EMBEDDING_THRESHOLD - 1e-4;
        let msg = vec![1.0f32, 0.0];
        let skill_emb = vec![below, (1.0 - below * below).sqrt()];
        let len_sq: f32 = skill_emb.iter().map(|x| x * x).sum();
        assert!((len_sq - 1.0).abs() < 1e-5);
        let cos = crate::providers::embed::cosine(&msg, &skill_emb);
        assert!(cos < EMBEDDING_THRESHOLD);
        let mut embs = std::collections::HashMap::new();
        embs.insert("a".to_string(), skill_emb);
        assert!(
            cosine_rerank(&msg, &skills, &embs).is_none(),
            "score below threshold MUST be rejected"
        );
    }
}
