//! Catalogue-wide ownership policy for automatic Skill routing aliases.
//!
//! A raw alias may appear more than once inside one Skill (for example a
//! punctuation variant or a parent/mode refinement), but two different Skill
//! owners may never claim the same normalized phrase. Runtime ties remain a
//! typed per-turn outcome; known catalogue collisions are rejected before a
//! generation can be installed, enabled, or hot-published.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::schema::{RuntimeSkill, Skill};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteAliasKind {
    ParentTrigger,
    ModeTrigger,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteAliasClaim {
    pub skill_id: String,
    pub mode_id: Option<String>,
    pub kind: RouteAliasKind,
    pub raw_alias: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteOwnerCollision {
    pub normalized_alias: String,
    pub claims: Vec<RouteAliasClaim>,
}

/// Normalize punctuation and Unicode whitespace without reducing matching to
/// ASCII. This is deliberately identical for parent and mode claims.
pub fn normalize_route_alias(alias: &str) -> String {
    let mut normalized = String::with_capacity(alias.len());
    let mut separator_pending = false;
    for character in alias.trim().chars() {
        for lowercase in character.to_lowercase() {
            if lowercase.is_alphanumeric() {
                if separator_pending && !normalized.is_empty() {
                    normalized.push(' ');
                }
                normalized.push(lowercase);
                separator_pending = false;
            } else {
                separator_pending = true;
            }
        }
    }
    normalized
}

pub(crate) fn inventory_collisions(skills: &[Skill]) -> Vec<RouteOwnerCollision> {
    find_collisions(skills.iter())
}

pub(crate) fn runtime_collisions(skills: &[RuntimeSkill]) -> Vec<RouteOwnerCollision> {
    find_collisions(skills.iter().map(RuntimeSkill::as_skill))
}

pub(crate) fn validate_inventory(skills: &[Skill]) -> Result<()> {
    validate_collisions(inventory_collisions(skills))
        .context("validate raw Skill route-alias ownership")
}

pub(crate) fn validate_runtime(skills: &[RuntimeSkill]) -> Result<()> {
    validate_collisions(runtime_collisions(skills))
        .context("validate authority-admitted Skill route-alias ownership")
}

fn find_collisions<'a>(skills: impl IntoIterator<Item = &'a Skill>) -> Vec<RouteOwnerCollision> {
    let mut claims = BTreeMap::<String, Vec<RouteAliasClaim>>::new();
    for skill in skills {
        for alias in &skill.manifest.trigger_keywords {
            record_claim(
                &mut claims,
                skill.id(),
                None,
                RouteAliasKind::ParentTrigger,
                alias,
            );
        }
        for mode in &skill.manifest.modes {
            for alias in &mode.trigger_phrases {
                record_claim(
                    &mut claims,
                    skill.id(),
                    Some(&mode.id),
                    RouteAliasKind::ModeTrigger,
                    alias,
                );
            }
        }
    }

    claims
        .into_iter()
        .filter_map(|(normalized_alias, mut claims)| {
            let owners = claims
                .iter()
                .map(|claim| claim.skill_id.as_str())
                .collect::<BTreeSet<_>>();
            if owners.len() < 2 {
                return None;
            }
            claims.sort_by(|left, right| {
                left.skill_id
                    .cmp(&right.skill_id)
                    .then_with(|| left.mode_id.cmp(&right.mode_id))
                    .then_with(|| left.raw_alias.cmp(&right.raw_alias))
            });
            claims.dedup();
            Some(RouteOwnerCollision {
                normalized_alias,
                claims,
            })
        })
        .collect()
}

fn record_claim(
    claims: &mut BTreeMap<String, Vec<RouteAliasClaim>>,
    skill_id: &str,
    mode_id: Option<&str>,
    kind: RouteAliasKind,
    raw_alias: &str,
) {
    let normalized = normalize_route_alias(raw_alias);
    if normalized.is_empty() {
        return;
    }
    claims.entry(normalized).or_default().push(RouteAliasClaim {
        skill_id: skill_id.to_owned(),
        mode_id: mode_id.map(str::to_owned),
        kind,
        raw_alias: raw_alias.to_owned(),
    });
}

fn validate_collisions(collisions: Vec<RouteOwnerCollision>) -> Result<()> {
    if collisions.is_empty() {
        return Ok(());
    }
    let summary = collisions
        .iter()
        .map(|collision| {
            let owners = collision
                .claims
                .iter()
                .map(|claim| match &claim.mode_id {
                    Some(mode) => format!("{}/{}", claim.skill_id, mode),
                    None => claim.skill_id.clone(),
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ");
            format!("`{}` -> {owners}", collision.normalized_alias)
        })
        .collect::<Vec<_>>()
        .join("; ");
    anyhow::bail!(
        "{} cross-owner Skill route-alias collision(s): {summary}",
        collisions.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skills::schema::{ModeEntry, OutputContract, Oversight, SkillManifest, Spectrum};

    fn skill(id: &str, triggers: &[&str], modes: Vec<ModeEntry>) -> Skill {
        let manifest = SkillManifest {
            id: id.to_owned(),
            description: format!("{id} skill"),
            version: "1.0.0".to_owned(),
            trigger_keywords: triggers.iter().map(|value| (*value).to_owned()).collect(),
            system_prompt: String::new(),
            tool_allowlist: Vec::new(),
            author: None,
            tags: Vec::new(),
            homepage: None,
            source: None,
            modes,
            enabled: true,
            delegate_to: None,
            model: None,
            paths: Vec::new(),
            effort: None,
            loop_trigger: false,
            visibility: crate::config::SkillVisibility::On,
        };
        Skill::from_trusted_bundled(
            manifest,
            std::path::PathBuf::from(format!("<fixture>/{id}/skill.yaml")),
            format!("hash-{id}"),
        )
    }

    fn mode(id: &str, triggers: &[&str]) -> ModeEntry {
        ModeEntry {
            id: id.to_owned(),
            description: format!("{id} mode"),
            spectrum: Spectrum::Balanced,
            oversight: Oversight::Medium,
            output: OutputContract {
                format: "markdown".to_owned(),
                length_hint: None,
            },
            trigger_phrases: triggers.iter().map(|value| (*value).to_owned()).collect(),
            system_prompt_delta: String::new(),
        }
    }

    #[test]
    fn punctuation_aliases_may_repeat_inside_one_owner() {
        let skills = vec![skill(
            "shipper",
            &["/ship", "ship"],
            vec![mode("ship-mode", &["ship!"])],
        )];
        assert!(inventory_collisions(&skills).is_empty());
    }

    #[test]
    fn parent_and_mode_claims_from_different_owners_conflict() {
        let skills = vec![
            skill("parent", &["Fact-Check"], Vec::new()),
            skill("mode-owner", &[], vec![mode("verify", &["fact check"])]),
        ];
        let collisions = inventory_collisions(&skills);
        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].normalized_alias, "fact check");
        assert_eq!(
            collisions[0]
                .claims
                .iter()
                .map(|claim| claim.skill_id.as_str())
                .collect::<Vec<_>>(),
            vec!["mode-owner", "parent"]
        );
        assert!(validate_inventory(&skills).is_err());
    }
}
