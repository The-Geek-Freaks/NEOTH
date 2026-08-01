//! One authority-bound skill decision for every runtime surface.
//!
//! A resolver owns the exact compound config+authority snapshot published by
//! the registry. A successful route keeps that publication alive, so
//! prompt/model/tool execution cannot detach a naked `&Skill` from the
//! authority generation that admitted it.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::registry::SkillSnapshot;
use super::router::{
    EMBEDDING_THRESHOLD, fuzzy_keyword_bonus, keyword_matches, keyword_weight, lowercase_tokens,
    passes_path_gate,
};
use super::schema::{ModeEntry, RuntimeSkill, Skill};

/// Ordered routing stage. The resolver never evaluates a later stage after an
/// earlier stage produced a match or conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillRouteStage {
    Explicit,
    ParentLiteral,
    Mode,
    Embedding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillRouteOutcome {
    Match,
    NoMatch,
    Conflict,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillRouteRejectionCode {
    EmptyExplicitSkill,
    ExplicitSkillUnavailable,
    ExplicitSkillDisabled,
    ExplicitSkillOutsidePathScope,
}

/// Exact installed/bundled identity carried into execution and route reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillExecutionBinding {
    pub trusted_bundled: bool,
    pub content_hash: String,
    pub package_generation_sha256: Option<String>,
    pub manifest_sha256: Option<String>,
    pub install_incarnation: Option<u64>,
    pub install_terminal_receipt_sha256: Option<String>,
    pub authority_record_sha256: Option<String>,
}

impl SkillExecutionBinding {
    fn from_runtime(skill: &RuntimeSkill) -> Self {
        Self {
            trusted_bundled: skill.is_trusted_bundled(),
            content_hash: skill.content_hash.clone(),
            package_generation_sha256: skill.package_generation_sha256().map(str::to_owned),
            manifest_sha256: skill.manifest_sha256().map(str::to_owned),
            install_incarnation: skill.install_incarnation(),
            install_terminal_receipt_sha256: skill
                .install_terminal_receipt_sha256()
                .map(str::to_owned),
            authority_record_sha256: skill.authority_record_sha256().map(str::to_owned),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkillRouteCandidateReport {
    pub skill_id: String,
    pub mode_id: Option<String>,
    pub matched_terms: Vec<String>,
    pub score: f32,
    pub execution: SkillExecutionBinding,
}

/// Stable JSON-ready explanation shared by Chat, channels, CLI and GUI/Buddy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkillRouteReport {
    pub outcome: SkillRouteOutcome,
    pub stage: Option<SkillRouteStage>,
    pub config_epoch: u64,
    pub authority_epoch: u64,
    pub snapshot_sha256: String,
    pub candidates: Vec<SkillRouteCandidateReport>,
    pub rejection: Option<SkillRouteRejectionCode>,
    /// Stable degradation code only; provider error strings never cross this
    /// report boundary.
    pub degraded_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedSkillRoute {
    snapshot: SkillSnapshot,
    skill_index: usize,
    mode_index: Option<usize>,
    report: SkillRouteReport,
}

impl ResolvedSkillRoute {
    pub fn runtime_skill(&self) -> &RuntimeSkill {
        &self.snapshot.skills()[self.skill_index]
    }

    pub fn skill(&self) -> &Skill {
        self.runtime_skill().as_skill()
    }

    pub fn mode(&self) -> Option<&ModeEntry> {
        self.mode_index
            .and_then(|index| self.skill().manifest.modes.get(index))
    }

    pub fn report(&self) -> &SkillRouteReport {
        &self.report
    }

    /// Thin parent prompt plus only the selected mode delta.
    pub fn system_prompt_layer(&self) -> Option<String> {
        let base = self.skill().system_prompt();
        match self.mode() {
            Some(mode) if !base.is_empty() && !mode.system_prompt_delta.is_empty() => {
                Some(format!("{base}\n\n{}", mode.system_prompt_delta))
            }
            Some(mode) if !mode.system_prompt_delta.is_empty() => {
                Some(mode.system_prompt_delta.clone())
            }
            _ if !base.is_empty() => Some(base.to_owned()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum SkillRouteDecision {
    Match(ResolvedSkillRoute),
    NoMatch(SkillRouteReport),
    Conflict(SkillRouteReport),
    Rejected(SkillRouteReport),
}

impl SkillRouteDecision {
    pub fn report(&self) -> &SkillRouteReport {
        match self {
            Self::Match(route) => route.report(),
            Self::NoMatch(report) | Self::Conflict(report) | Self::Rejected(report) => report,
        }
    }

    pub fn into_match(self) -> Option<ResolvedSkillRoute> {
        match self {
            Self::Match(route) => Some(route),
            Self::NoMatch(_) | Self::Conflict(_) | Self::Rejected(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SkillRouteRequest<'a> {
    pub message: &'a str,
    pub explicit_skill_id: Option<&'a str>,
    pub min_literal_weight: usize,
    pub active_files: &'a [String],
}

impl<'a> SkillRouteRequest<'a> {
    pub fn automatic(
        message: &'a str,
        min_literal_weight: usize,
        active_files: &'a [String],
    ) -> Self {
        Self {
            message,
            explicit_skill_id: None,
            min_literal_weight,
            active_files,
        }
    }

    pub fn with_explicit_skill(mut self, explicit_skill_id: Option<&'a str>) -> Self {
        self.explicit_skill_id = explicit_skill_id;
        self
    }
}

/// Editor context shared by every interactive CLI routing surface. Channel
/// turns deliberately pass an empty slice because they have no local editor
/// session to attest. Empty or unset input preserves the established
/// all-paths-eligible behaviour.
pub fn active_files_from_env() -> Vec<String> {
    let separator = if cfg!(windows) { ';' } else { ':' };
    std::env::var("NEOTH_ACTIVE_FILES")
        .unwrap_or_default()
        .split(separator)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// Resolver over one immutable, authority-admitted runtime snapshot.
#[derive(Debug, Clone)]
pub struct SkillRouteResolver {
    snapshot: SkillSnapshot,
    eligible_indices: Arc<Vec<usize>>,
    snapshot_sha256: String,
}

#[derive(Debug, Clone)]
struct RankedCandidate {
    skill_index: usize,
    mode_index: Option<usize>,
    matched_terms: Vec<String>,
    score: f32,
}

enum UniqueTop {
    None,
    One(RankedCandidate),
    Conflict(Vec<RankedCandidate>),
}

impl SkillRouteResolver {
    pub fn new(snapshot: SkillSnapshot) -> Self {
        let eligible_indices = Arc::new((0..snapshot.skills().len()).collect::<Vec<_>>());
        let snapshot_sha256 = snapshot_fingerprint(&snapshot, eligible_indices.as_slice());
        Self {
            snapshot,
            eligible_indices,
            snapshot_sha256,
        }
    }

    /// Restrict the effective routing view without cloning or detaching any
    /// RuntimeSkill. The original compound authority snapshot remains owned by
    /// every match; only admitted indices participate in this resolver view.
    pub fn retaining(mut self, mut keep: impl FnMut(&RuntimeSkill) -> bool) -> Self {
        self.eligible_indices = Arc::new(
            self.eligible_indices
                .iter()
                .copied()
                .filter(|&index| keep(&self.snapshot.skills()[index]))
                .collect(),
        );
        self.snapshot_sha256 =
            snapshot_fingerprint(&self.snapshot, self.eligible_indices.as_slice());
        self
    }

    pub fn snapshot_sha256(&self) -> &str {
        &self.snapshot_sha256
    }

    pub fn snapshot(&self) -> SkillSnapshot {
        self.snapshot.clone()
    }

    /// Resolve one turn. Precedence is strict:
    /// explicit id -> parent literal -> mode -> embedding. Embedding is never
    /// invoked after any literal match or conflict.
    pub async fn resolve(
        &self,
        request: SkillRouteRequest<'_>,
        embed_provider: Option<&dyn crate::providers::embed::EmbedProvider>,
    ) -> SkillRouteDecision {
        if let Some(explicit) = request.explicit_skill_id {
            return self.resolve_explicit(request, explicit);
        }

        let eligible = self.auto_eligible_indices(request.active_files);
        match unique_top(self.literal_candidates(request, &eligible)) {
            UniqueTop::Conflict(candidates) => {
                return self.conflict(SkillRouteStage::ParentLiteral, candidates);
            }
            UniqueTop::One(parent) => return self.resolve_parent_mode(request.message, parent),
            UniqueTop::None => {}
        }

        match unique_top(self.mode_candidates(request.message, &eligible)) {
            UniqueTop::Conflict(candidates) => {
                return self.conflict(SkillRouteStage::Mode, candidates);
            }
            UniqueTop::One(candidate) => return self.matched(SkillRouteStage::Mode, candidate),
            UniqueTop::None => {}
        }

        let Some(provider) = embed_provider else {
            return self.no_match(None);
        };
        self.resolve_embedding(request.message, provider, &eligible)
            .await
    }

    fn resolve_explicit(
        &self,
        request: SkillRouteRequest<'_>,
        explicit: &str,
    ) -> SkillRouteDecision {
        let requested = explicit.trim().trim_start_matches('/');
        if requested.is_empty() {
            return self.rejected(SkillRouteRejectionCode::EmptyExplicitSkill);
        }
        let matches = self
            .eligible_indices
            .iter()
            .copied()
            .filter(|&index| {
                self.snapshot.skills()[index]
                    .id()
                    .eq_ignore_ascii_case(requested)
            })
            .collect::<Vec<_>>();
        if matches.is_empty() {
            return self.rejected(SkillRouteRejectionCode::ExplicitSkillUnavailable);
        }
        if matches.len() > 1 {
            let candidates = matches
                .into_iter()
                .map(|skill_index| RankedCandidate {
                    skill_index,
                    mode_index: None,
                    matched_terms: vec![requested.to_owned()],
                    score: 1.0,
                })
                .collect();
            return self.conflict(SkillRouteStage::Explicit, candidates);
        }
        let skill_index = matches[0];
        let skill = &self.snapshot.skills()[skill_index];
        if !skill.is_enabled() {
            return self.rejected(SkillRouteRejectionCode::ExplicitSkillDisabled);
        }
        if !passes_path_gate(skill.paths(), request.active_files) {
            return self.rejected(SkillRouteRejectionCode::ExplicitSkillOutsidePathScope);
        }

        let parent = RankedCandidate {
            skill_index,
            mode_index: None,
            matched_terms: vec![requested.to_owned()],
            score: 1.0,
        };
        self.resolve_parent_mode_with_stage(request.message, parent, SkillRouteStage::Explicit)
    }

    fn resolve_parent_mode(&self, message: &str, parent: RankedCandidate) -> SkillRouteDecision {
        self.resolve_parent_mode_with_stage(message, parent, SkillRouteStage::ParentLiteral)
    }

    fn resolve_parent_mode_with_stage(
        &self,
        message: &str,
        parent: RankedCandidate,
        stage: SkillRouteStage,
    ) -> SkillRouteDecision {
        match unique_top(self.mode_candidates(message, &[parent.skill_index])) {
            UniqueTop::Conflict(candidates) => self.conflict(SkillRouteStage::Mode, candidates),
            UniqueTop::One(mut mode) => {
                if stage == SkillRouteStage::Explicit {
                    mode.matched_terms.insert(
                        0,
                        self.snapshot.skills()[parent.skill_index].id().to_owned(),
                    );
                }
                self.matched(stage, mode)
            }
            UniqueTop::None => self.matched(stage, parent),
        }
    }

    fn auto_eligible_indices(&self, active_files: &[String]) -> Vec<usize> {
        self.eligible_indices
            .iter()
            .copied()
            .filter(|&index| {
                let skill = &self.snapshot.skills()[index];
                skill.is_enabled()
                    && skill.visibility() == crate::config::SkillVisibility::On
                    && passes_path_gate(skill.paths(), active_files)
            })
            .collect()
    }

    fn literal_candidates(
        &self,
        request: SkillRouteRequest<'_>,
        eligible: &[usize],
    ) -> Vec<RankedCandidate> {
        let lower_message = request.message.to_lowercase();
        let tokens = lowercase_tokens(&lower_message);
        if tokens.is_empty() {
            return Vec::new();
        }
        eligible
            .iter()
            .filter_map(|&skill_index| {
                let skill = &self.snapshot.skills()[skill_index];
                let mut hits = Vec::new();
                let mut exact_weight = 0usize;
                for keyword in skill.trigger_keywords() {
                    let normalized = keyword.trim().to_lowercase();
                    if normalized.is_empty() || hits.contains(&normalized) {
                        continue;
                    }
                    if keyword_matches(&normalized, &tokens, &lower_message) {
                        exact_weight += keyword_weight(&normalized);
                        hits.push(normalized);
                    }
                }
                let fuzzy = fuzzy_keyword_bonus(skill.trigger_keywords(), &tokens, &hits);
                let score = exact_weight * 2 + fuzzy;
                let floor = request.min_literal_weight.max(1) * 2;
                if score < floor || (hits.is_empty() && fuzzy == 0) {
                    return None;
                }
                Some(RankedCandidate {
                    skill_index,
                    mode_index: None,
                    matched_terms: hits,
                    score: score as f32,
                })
            })
            .collect()
    }

    fn mode_candidates(&self, message: &str, eligible: &[usize]) -> Vec<RankedCandidate> {
        let lower_message = message.to_lowercase();
        let tokens = lowercase_tokens(&lower_message);
        eligible
            .iter()
            .flat_map(|&skill_index| {
                self.snapshot.skills()[skill_index]
                    .manifest
                    .modes
                    .iter()
                    .enumerate()
                    .filter_map({
                        let lower_message = &lower_message;
                        let tokens = &tokens;
                        move |(mode_index, mode)| {
                            let mut terms = Vec::new();
                            let mut score = 0usize;
                            for phrase in &mode.trigger_phrases {
                                let normalized = phrase.trim().to_lowercase();
                                if normalized.is_empty() || terms.contains(&normalized) {
                                    continue;
                                }
                                if keyword_matches(&normalized, tokens, lower_message) {
                                    score += keyword_weight(&normalized);
                                    terms.push(normalized);
                                }
                            }
                            (score > 0).then_some(RankedCandidate {
                                skill_index,
                                mode_index: Some(mode_index),
                                matched_terms: terms,
                                score: score as f32,
                            })
                        }
                    })
            })
            .collect()
    }

    async fn resolve_embedding(
        &self,
        message: &str,
        provider: &dyn crate::providers::embed::EmbedProvider,
        eligible: &[usize],
    ) -> SkillRouteDecision {
        use crate::providers::embed::EmbedRequest;

        if message.trim().is_empty() {
            return self.no_match(None);
        }
        let message_embedding = match provider.embed(EmbedRequest::new(message)).await {
            Ok(response) => response.vector,
            Err(error) => {
                tracing::warn!(
                    provider = provider.name(),
                    error = %error,
                    "skill resolver message embedding failed"
                );
                return self.no_match(Some("message_embedding_failed"));
            }
        };

        let mut failures = 0usize;
        let mut candidates = Vec::new();
        for &skill_index in eligible {
            let skill = &self.snapshot.skills()[skill_index];
            if skill.description().trim().is_empty() {
                continue;
            }
            let response = match provider
                .embed(EmbedRequest::new(skill.description().to_owned()))
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    failures += 1;
                    tracing::warn!(
                        provider = provider.name(),
                        skill = skill.id(),
                        error = %error,
                        "skill resolver candidate embedding failed"
                    );
                    continue;
                }
            };
            let score = crate::providers::embed::cosine(&message_embedding, &response.vector);
            if score.is_finite() && score >= EMBEDDING_THRESHOLD {
                candidates.push(RankedCandidate {
                    skill_index,
                    mode_index: None,
                    matched_terms: Vec::new(),
                    score,
                });
            }
        }
        match unique_top(candidates) {
            UniqueTop::Conflict(candidates) => {
                self.conflict(SkillRouteStage::Embedding, candidates)
            }
            UniqueTop::One(candidate) => self.matched(SkillRouteStage::Embedding, candidate),
            UniqueTop::None if failures > 0 => self.no_match(Some("skill_embedding_failed")),
            UniqueTop::None => self.no_match(None),
        }
    }

    fn matched(&self, stage: SkillRouteStage, candidate: RankedCandidate) -> SkillRouteDecision {
        let report = self.report(
            SkillRouteOutcome::Match,
            Some(stage),
            vec![candidate.clone()],
            None,
            None,
        );
        SkillRouteDecision::Match(ResolvedSkillRoute {
            snapshot: self.snapshot.clone(),
            skill_index: candidate.skill_index,
            mode_index: candidate.mode_index,
            report,
        })
    }

    fn conflict(
        &self,
        stage: SkillRouteStage,
        candidates: Vec<RankedCandidate>,
    ) -> SkillRouteDecision {
        SkillRouteDecision::Conflict(self.report(
            SkillRouteOutcome::Conflict,
            Some(stage),
            candidates,
            None,
            None,
        ))
    }

    fn rejected(&self, rejection: SkillRouteRejectionCode) -> SkillRouteDecision {
        SkillRouteDecision::Rejected(self.report(
            SkillRouteOutcome::Rejected,
            Some(SkillRouteStage::Explicit),
            Vec::new(),
            Some(rejection),
            None,
        ))
    }

    fn no_match(&self, degraded_reason: Option<&str>) -> SkillRouteDecision {
        SkillRouteDecision::NoMatch(self.report(
            SkillRouteOutcome::NoMatch,
            None,
            Vec::new(),
            None,
            degraded_reason,
        ))
    }

    fn report(
        &self,
        outcome: SkillRouteOutcome,
        stage: Option<SkillRouteStage>,
        mut candidates: Vec<RankedCandidate>,
        rejection: Option<SkillRouteRejectionCode>,
        degraded_reason: Option<&str>,
    ) -> SkillRouteReport {
        candidates.sort_by(|left, right| {
            let left_skill = &self.snapshot.skills()[left.skill_index];
            let right_skill = &self.snapshot.skills()[right.skill_index];
            left_skill.id().cmp(right_skill.id()).then_with(|| {
                let left_mode = left
                    .mode_index
                    .and_then(|index| left_skill.manifest.modes.get(index))
                    .map(|mode| mode.id.as_str())
                    .unwrap_or("");
                let right_mode = right
                    .mode_index
                    .and_then(|index| right_skill.manifest.modes.get(index))
                    .map(|mode| mode.id.as_str())
                    .unwrap_or("");
                left_mode.cmp(right_mode)
            })
        });
        SkillRouteReport {
            outcome,
            stage,
            config_epoch: self.snapshot.config_epoch(),
            authority_epoch: self.snapshot.authority_epoch(),
            snapshot_sha256: self.snapshot_sha256.clone(),
            candidates: candidates
                .into_iter()
                .map(|candidate| {
                    let skill = &self.snapshot.skills()[candidate.skill_index];
                    SkillRouteCandidateReport {
                        skill_id: skill.id().to_owned(),
                        mode_id: candidate.mode_index.and_then(|index| {
                            skill.manifest.modes.get(index).map(|mode| mode.id.clone())
                        }),
                        matched_terms: candidate.matched_terms,
                        score: candidate.score,
                        execution: SkillExecutionBinding::from_runtime(skill),
                    }
                })
                .collect(),
            rejection,
            degraded_reason: degraded_reason.map(str::to_owned),
        }
    }
}

fn unique_top(candidates: Vec<RankedCandidate>) -> UniqueTop {
    let Some(best_score) = candidates
        .iter()
        .map(|candidate| candidate.score)
        .max_by(f32::total_cmp)
    else {
        return UniqueTop::None;
    };
    let mut top = candidates
        .into_iter()
        .filter(|candidate| candidate.score == best_score)
        .collect::<Vec<_>>();
    if top.len() == 1 {
        UniqueTop::One(top.pop().expect("one route candidate"))
    } else {
        UniqueTop::Conflict(top)
    }
}

fn snapshot_fingerprint(snapshot: &SkillSnapshot, eligible_indices: &[usize]) -> String {
    fn field(hasher: &mut Sha256, value: &str) {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }

    let mut hasher = Sha256::new();
    hasher.update(snapshot.config_epoch().to_be_bytes());
    hasher.update(snapshot.authority_epoch().to_be_bytes());
    hasher.update((eligible_indices.len() as u64).to_be_bytes());
    for &index in eligible_indices {
        let skill = &snapshot.skills()[index];
        field(&mut hasher, skill.id());
        field(&mut hasher, &skill.content_hash);
        field(
            &mut hasher,
            skill.package_generation_sha256().unwrap_or("<bundled>"),
        );
        field(
            &mut hasher,
            skill.authority_record_sha256().unwrap_or("<bundled>"),
        );
    }
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::skills::schema::{ModeEntry, OutputContract, Oversight, SkillManifest, Spectrum};

    fn runtime_skill(
        id: &str,
        keywords: &[&str],
        visibility: crate::config::SkillVisibility,
        modes: Vec<ModeEntry>,
    ) -> RuntimeSkill {
        runtime_skill_with_paths(id, keywords, visibility, modes, Vec::new())
    }

    fn runtime_skill_with_paths(
        id: &str,
        keywords: &[&str],
        visibility: crate::config::SkillVisibility,
        modes: Vec<ModeEntry>,
        paths: Vec<String>,
    ) -> RuntimeSkill {
        let manifest = SkillManifest {
            id: id.to_owned(),
            description: format!("{id} description"),
            version: "1.0.0".to_owned(),
            trigger_keywords: keywords.iter().map(|value| (*value).to_owned()).collect(),
            system_prompt: format!("{id} base"),
            tool_allowlist: Vec::new(),
            author: None,
            tags: Vec::new(),
            homepage: None,
            source: None,
            modes,
            enabled: true,
            delegate_to: None,
            model: None,
            paths,
            effort: None,
            loop_trigger: false,
            visibility,
        };
        RuntimeSkill::from_trusted_bundled(Skill::from_trusted_bundled(
            manifest,
            std::path::PathBuf::from(format!("<bundled>/{id}/skill.yaml")),
            format!("hash-{id}"),
        ))
        .unwrap()
    }

    fn mode(id: &str, triggers: &[&str], delta: &str) -> ModeEntry {
        ModeEntry {
            id: id.to_owned(),
            description: format!("mode {id}"),
            spectrum: Spectrum::Balanced,
            oversight: Oversight::Medium,
            output: OutputContract {
                format: "markdown".to_owned(),
                length_hint: None,
            },
            trigger_phrases: triggers.iter().map(|value| (*value).to_owned()).collect(),
            system_prompt_delta: delta.to_owned(),
        }
    }

    fn resolver(skills: Vec<RuntimeSkill>) -> SkillRouteResolver {
        SkillRouteResolver::new(SkillSnapshot::from_test_skills(skills))
    }

    #[tokio::test]
    async fn explicit_selection_wins_and_retains_manual_visibility() {
        let resolver = resolver(vec![
            runtime_skill(
                "manual",
                &[],
                crate::config::SkillVisibility::UserInvocableOnly,
                Vec::new(),
            ),
            runtime_skill(
                "automatic",
                &["deploy"],
                crate::config::SkillVisibility::On,
                Vec::new(),
            ),
        ]);
        let request =
            SkillRouteRequest::automatic("deploy now", 1, &[]).with_explicit_skill(Some("manual"));
        let SkillRouteDecision::Match(route) = resolver.resolve(request, None).await else {
            panic!("explicit skill must match");
        };
        assert_eq!(route.skill().id(), "manual");
        assert_eq!(route.report().stage, Some(SkillRouteStage::Explicit));
    }

    #[tokio::test]
    async fn automatic_routing_excludes_both_manual_visibility_classes() {
        let resolver = resolver(vec![
            runtime_skill(
                "name-only",
                &["hidden-name"],
                crate::config::SkillVisibility::NameOnly,
                vec![mode("name-mode", &["hidden-name-mode"], "name")],
            ),
            runtime_skill(
                "user-only",
                &["hidden-user"],
                crate::config::SkillVisibility::UserInvocableOnly,
                vec![mode("user-mode", &["hidden-user-mode"], "user")],
            ),
            runtime_skill(
                "visible",
                &["visible"],
                crate::config::SkillVisibility::On,
                Vec::new(),
            ),
        ]);

        for prompt in [
            "hidden-name",
            "hidden-name-mode",
            "hidden-user",
            "hidden-user-mode",
        ] {
            let decision = resolver
                .resolve(SkillRouteRequest::automatic(prompt, 1, &[]), None)
                .await;
            assert!(
                matches!(decision, SkillRouteDecision::NoMatch(_)),
                "manual-only Skill must not auto-route for {prompt}: {decision:?}"
            );
        }
        let SkillRouteDecision::Match(route) = resolver
            .resolve(SkillRouteRequest::automatic("visible", 1, &[]), None)
            .await
        else {
            panic!("On Skill must remain auto-routable");
        };
        assert_eq!(route.skill().id(), "visible");
    }

    #[tokio::test]
    async fn unknown_explicit_selection_is_rejected_not_auto_routed() {
        let resolver = resolver(vec![runtime_skill(
            "automatic",
            &["deploy"],
            crate::config::SkillVisibility::On,
            Vec::new(),
        )]);
        let request =
            SkillRouteRequest::automatic("deploy now", 1, &[]).with_explicit_skill(Some("missing"));
        let SkillRouteDecision::Rejected(report) = resolver.resolve(request, None).await else {
            panic!("unknown explicit selection must reject");
        };
        assert_eq!(
            report.rejection,
            Some(SkillRouteRejectionCode::ExplicitSkillUnavailable)
        );
    }

    #[tokio::test]
    async fn parent_literal_precedes_other_skills_global_mode() {
        let resolver = resolver(vec![
            runtime_skill(
                "parent",
                &["review"],
                crate::config::SkillVisibility::On,
                Vec::new(),
            ),
            runtime_skill(
                "mode-owner",
                &[],
                crate::config::SkillVisibility::On,
                vec![mode("review-mode", &["review"], "other delta")],
            ),
        ]);
        let SkillRouteDecision::Match(route) = resolver
            .resolve(SkillRouteRequest::automatic("review this", 1, &[]), None)
            .await
        else {
            panic!("parent must match");
        };
        assert_eq!(route.skill().id(), "parent");
        assert!(route.mode().is_none());
        assert_eq!(route.report().stage, Some(SkillRouteStage::ParentLiteral));
    }

    #[tokio::test]
    async fn selected_parent_may_refine_to_its_own_mode() {
        let resolver = resolver(vec![runtime_skill(
            "research",
            &["research"],
            crate::config::SkillVisibility::On,
            vec![mode("systematic", &["systematic review"], "MODE")],
        )]);
        let SkillRouteDecision::Match(route) = resolver
            .resolve(
                SkillRouteRequest::automatic("research a systematic review", 1, &[]),
                None,
            )
            .await
        else {
            panic!("parent mode must match");
        };
        assert_eq!(route.skill().id(), "research");
        assert_eq!(
            route.mode().map(|value| value.id.as_str()),
            Some("systematic")
        );
        assert_eq!(
            route.system_prompt_layer().as_deref(),
            Some("research base\n\nMODE")
        );
    }

    #[tokio::test]
    async fn equal_parent_scores_are_a_typed_conflict() {
        let resolver = resolver(vec![
            runtime_skill(
                "zeta",
                &["news"],
                crate::config::SkillVisibility::On,
                Vec::new(),
            ),
            runtime_skill(
                "alpha",
                &["news"],
                crate::config::SkillVisibility::On,
                Vec::new(),
            ),
        ]);
        let SkillRouteDecision::Conflict(report) = resolver
            .resolve(SkillRouteRequest::automatic("news", 1, &[]), None)
            .await
        else {
            panic!("tie must conflict");
        };
        assert_eq!(report.stage, Some(SkillRouteStage::ParentLiteral));
        assert_eq!(
            report
                .candidates
                .iter()
                .map(|candidate| candidate.skill_id.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "zeta"]
        );
    }

    #[tokio::test]
    async fn equal_global_mode_scores_are_a_typed_conflict() {
        let resolver = resolver(vec![
            runtime_skill(
                "zeta",
                &[],
                crate::config::SkillVisibility::On,
                vec![mode("zeta-mode", &["inspect deeply"], "zeta")],
            ),
            runtime_skill(
                "alpha",
                &[],
                crate::config::SkillVisibility::On,
                vec![mode("alpha-mode", &["inspect deeply"], "alpha")],
            ),
        ]);
        let SkillRouteDecision::Conflict(report) = resolver
            .resolve(SkillRouteRequest::automatic("inspect deeply", 1, &[]), None)
            .await
        else {
            panic!("global mode tie must conflict");
        };
        assert_eq!(report.stage, Some(SkillRouteStage::Mode));
        assert_eq!(
            report
                .candidates
                .iter()
                .map(|candidate| candidate.skill_id.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "zeta"]
        );
    }

    #[tokio::test]
    async fn path_scope_applies_before_literal_mode_embedding_and_explicit_routing() {
        let resolver = resolver(vec![runtime_skill_with_paths(
            "scoped",
            &["deploy"],
            crate::config::SkillVisibility::On,
            vec![mode("scoped-mode", &["release carefully"], "scope")],
            vec!["src/**".to_owned()],
        )]);
        let active_files = vec!["docs/readme.md".to_owned()];
        let embedder = CountingEmbedder {
            calls: AtomicUsize::new(0),
        };

        for prompt in ["deploy", "release carefully", "semantic request"] {
            let decision = resolver
                .resolve(
                    SkillRouteRequest::automatic(prompt, 1, &active_files),
                    Some(&embedder),
                )
                .await;
            assert!(
                matches!(decision, SkillRouteDecision::NoMatch(_)),
                "out-of-scope Skill must not route for {prompt}: {decision:?}"
            );
        }
        assert_eq!(
            embedder.calls.load(Ordering::SeqCst),
            3,
            "embedding may inspect the message after literal NoMatch but must never embed the ineligible Skill"
        );

        let SkillRouteDecision::Rejected(report) = resolver
            .resolve(
                SkillRouteRequest::automatic("deploy", 1, &active_files)
                    .with_explicit_skill(Some("scoped")),
                None,
            )
            .await
        else {
            panic!("explicit out-of-scope selection must reject");
        };
        assert_eq!(
            report.rejection,
            Some(SkillRouteRejectionCode::ExplicitSkillOutsidePathScope)
        );
    }

    struct CountingEmbedder {
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl crate::providers::embed::EmbedProvider for CountingEmbedder {
        fn name(&self) -> &'static str {
            "counting"
        }

        fn default_dim(&self) -> usize {
            2
        }

        async fn embed(
            &self,
            _request: crate::providers::embed::EmbedRequest,
        ) -> anyhow::Result<crate::providers::embed::EmbedResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(crate::providers::embed::EmbedResponse {
                vector: vec![1.0, 0.0],
                model: "counting".to_owned(),
                latency: std::time::Duration::ZERO,
            })
        }
    }

    struct FailingEmbedder;

    #[async_trait::async_trait]
    impl crate::providers::embed::EmbedProvider for FailingEmbedder {
        fn name(&self) -> &'static str {
            "failing"
        }

        fn default_dim(&self) -> usize {
            2
        }

        async fn embed(
            &self,
            _request: crate::providers::embed::EmbedRequest,
        ) -> anyhow::Result<crate::providers::embed::EmbedResponse> {
            anyhow::bail!("fixture failure")
        }
    }

    #[tokio::test]
    async fn embedding_is_never_called_after_literal_match() {
        let resolver = resolver(vec![runtime_skill(
            "literal",
            &["deploy"],
            crate::config::SkillVisibility::On,
            Vec::new(),
        )]);
        let embedder = CountingEmbedder {
            calls: AtomicUsize::new(0),
        };
        let decision = resolver
            .resolve(
                SkillRouteRequest::automatic("deploy", 1, &[]),
                Some(&embedder),
            )
            .await;
        assert!(matches!(decision, SkillRouteDecision::Match(_)));
        assert_eq!(embedder.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn equal_embedding_scores_are_a_typed_conflict() {
        let resolver = resolver(vec![
            runtime_skill("zeta", &[], crate::config::SkillVisibility::On, Vec::new()),
            runtime_skill("alpha", &[], crate::config::SkillVisibility::On, Vec::new()),
        ]);
        let embedder = CountingEmbedder {
            calls: AtomicUsize::new(0),
        };
        let SkillRouteDecision::Conflict(report) = resolver
            .resolve(
                SkillRouteRequest::automatic("semantic request", 1, &[]),
                Some(&embedder),
            )
            .await
        else {
            panic!("equal embedding scores must conflict");
        };
        assert_eq!(report.stage, Some(SkillRouteStage::Embedding));
        assert_eq!(
            report
                .candidates
                .iter()
                .map(|candidate| candidate.skill_id.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "zeta"]
        );
    }

    #[tokio::test]
    async fn embedding_failure_is_visible_as_a_degraded_no_match() {
        let resolver = resolver(vec![runtime_skill(
            "semantic",
            &[],
            crate::config::SkillVisibility::On,
            Vec::new(),
        )]);
        let SkillRouteDecision::NoMatch(report) = resolver
            .resolve(
                SkillRouteRequest::automatic("semantic request", 1, &[]),
                Some(&FailingEmbedder),
            )
            .await
        else {
            panic!("provider failure must degrade to an explained NoMatch");
        };
        assert_eq!(
            report.degraded_reason.as_deref(),
            Some("message_embedding_failed")
        );
    }

    #[tokio::test]
    async fn resolved_route_owns_the_authority_snapshot() {
        let snapshot = SkillSnapshot::from_test_skills(vec![runtime_skill(
            "owned",
            &["owned"],
            crate::config::SkillVisibility::On,
            Vec::new(),
        )]);
        let resolver = SkillRouteResolver::new(snapshot.clone());
        let SkillRouteDecision::Match(route) = resolver
            .resolve(SkillRouteRequest::automatic("owned", 1, &[]), None)
            .await
        else {
            panic!("skill must match");
        };
        drop(snapshot);
        drop(resolver);
        assert_eq!(route.skill().id(), "owned");
        assert!(route.report().candidates[0].execution.trusted_bundled);
    }
}
