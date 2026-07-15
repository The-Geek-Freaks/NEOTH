//! Ground-truth onboarding wizard sub-step — Phase 28c R-24 GT-4 + GT-5.
//!
//! Loads the bilingual question bank (`~/.neoth/wizard/groundtruth-questions.yaml`,
//! falling back to the daemon-bundled copy at `assets/wizard/...`) and walks
//! the operator through the 25 default questions. Each answer becomes one
//! `idx_groundtruth` row with `source = "onboarding"`.
//!
//! v0.1 implements the **Q&A interactive path only** per the ship-priority
//! memo (`memory/neoth_gt_onboarding_pins.md`). Paste-text, infra-scan, and
//! foreign-agent import paths land in v0.1.x / v0.2 as the `neoth import`
//! subcommand.
//!
//! Skipping is first-class: any question marked `skip_ok: true` accepts an
//! empty Enter and is recorded as "operator skipped". Required questions
//! re-prompt until non-empty.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::config::FreedomConfig;
use crate::memory::groundtruth;
use crate::memory::store;

/// YAML root.
#[derive(Debug, Deserialize)]
pub struct QuestionBank {
    pub version: u32,
    pub questions: Vec<Question>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Question {
    pub id: String,
    pub category: String,
    pub prompt: BilingualPrompt,
    #[serde(default)]
    pub placeholder: Option<String>,
    #[serde(default = "default_scope")]
    pub scope: String,
    #[serde(default)]
    pub skip_ok: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BilingualPrompt {
    pub en: String,
    pub de: String,
}

fn default_scope() -> String {
    "global".into()
}

/// Pick the prompt that matches `lang_primary`. Falls back to English on
/// anything not exactly `"de"` so unsupported language codes don't crash.
pub fn pick_prompt<'a>(p: &'a BilingualPrompt, lang_primary: &str) -> &'a str {
    match lang_primary {
        "de" | "de-DE" | "de-AT" | "de-CH" => &p.de,
        _ => &p.en,
    }
}

impl QuestionBank {
    pub fn parse(yaml: &str) -> Result<Self> {
        let parsed: Self = serde_yaml::from_str(yaml).context("parse question bank YAML")?;
        if parsed.version != 1 {
            anyhow::bail!(
                "question bank version {} not supported (expected 1)",
                parsed.version,
            );
        }
        Ok(parsed)
    }

    /// Load from disk. Returns `None` if the file is missing (caller can
    /// fall back to the bundled default).
    pub fn load_from(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("read question bank {}", path.display()))?;
        Self::parse(&body).map(Some)
    }

    /// Default on-disk location: `~/.neoth/wizard/groundtruth-questions.yaml`.
    pub fn default_path() -> PathBuf {
        FreedomConfig::default_neoth_home()
            .join("wizard")
            .join("groundtruth-questions.yaml")
    }
}

/// Persisted answer for one question. `value = None` means operator skipped.
#[derive(Debug, Clone, PartialEq)]
pub struct Answer {
    pub question_id: String,
    pub category: String,
    pub scope: String,
    pub value: Option<String>,
}

/// Format an answer as the `statement` field of an `idx_groundtruth` row.
/// "operator says <prompt>: <value>" keeps the row self-explanatory when
/// the question bank evolves and prompts change.
pub fn statement_for(question_prompt: &str, value: &str) -> String {
    format!("{}: {}", question_prompt.trim_end_matches('?'), value)
}

/// Persist a batch of answers into `idx_groundtruth`. Returns how many rows
/// were inserted (skipped answers count as zero).
pub fn persist_answers(
    db_path: &Path,
    bank: &QuestionBank,
    answers: &[Answer],
    lang_primary: &str,
    now_ns: i64,
) -> Result<usize> {
    let conn = store::open(db_path)?;
    let mut inserted = 0usize;
    for a in answers {
        let Some(value) = a.value.as_deref() else {
            continue;
        };
        if value.trim().is_empty() {
            continue;
        }
        let q = bank
            .questions
            .iter()
            .find(|q| q.id == a.question_id)
            .ok_or_else(|| anyhow::anyhow!("unknown question id `{}`", a.question_id))?;
        let prompt = pick_prompt(&q.prompt, lang_primary);
        let statement = statement_for(prompt, value);
        groundtruth::insert(
            &conn,
            &statement,
            &groundtruth::Source::Onboarding,
            &a.scope,
            now_ns,
        )?;
        inserted += 1;
    }
    Ok(inserted)
}

/// Run the interactive Q&A pass. Returns the collected [`Answer`]s.
/// Pure data — caller decides when to call [`persist_answers`].
///
/// Non-interactive builds (no `wizard` feature) return an empty answer list
/// so the operator can run `neoth groundtruth add` instead.
pub fn run_qa(bank: &QuestionBank, lang_primary: &str) -> Result<Vec<Answer>> {
    #[cfg(feature = "wizard")]
    {
        let mut answers = Vec::with_capacity(bank.questions.len());
        let mut current_category = String::new();
        for q in &bank.questions {
            if q.category != current_category {
                println!("\n── {} ──", q.category);
                current_category = q.category.clone();
            }
            let prompt = pick_prompt(&q.prompt, lang_primary);
            let hint = q
                .placeholder
                .as_deref()
                .map(|p| format!(" ({p})"))
                .unwrap_or_default();
            let label = format!("{prompt}{hint}");
            let raw = if q.skip_ok {
                dialoguer::Input::<String>::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt(&label)
                    .allow_empty(true)
                    .interact_text()
                    .context("groundtruth Q&A input")?
            } else {
                dialoguer::Input::<String>::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt(&label)
                    .validate_with(|s: &String| -> std::result::Result<(), &str> {
                        if s.trim().is_empty() {
                            Err("required — please provide an answer")
                        } else {
                            Ok(())
                        }
                    })
                    .interact_text()
                    .context("groundtruth Q&A input")?
            };
            let value = if raw.trim().is_empty() {
                None
            } else {
                Some(raw.trim().to_string())
            };
            answers.push(Answer {
                question_id: q.id.clone(),
                category: q.category.clone(),
                scope: q.scope.clone(),
                value,
            });
        }
        Ok(answers)
    }
    #[cfg(not(feature = "wizard"))]
    {
        let _ = (bank, lang_primary);
        Ok(Vec::new())
    }
}

/// Bundled default question bank. Compiled into the binary so a fresh
/// install works even before `~/.neoth/wizard/groundtruth-questions.yaml`
/// exists. Source: `assets/wizard/groundtruth-questions.yaml`.
pub const BUNDLED_QUESTIONS_YAML: &str =
    include_str!("../../assets/wizard/groundtruth-questions.yaml");

/// Load the question bank: prefer the operator-editable copy on disk, fall
/// back to the bundled default.
pub fn load_bank() -> Result<QuestionBank> {
    let path = QuestionBank::default_path();
    if let Some(b) = QuestionBank::load_from(&path)? {
        return Ok(b);
    }
    QuestionBank::parse(BUNDLED_QUESTIONS_YAML)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn bundled_yaml_parses_with_expected_question_count() {
        // The memo header (`memory/neoth_gt_onboarding_pins.md`) says "25
        // questions" but the per-category breakdown sums to 23. The bank
        // is operator-editable so the count is not load-bearing — we
        // assert the actual shipped count and the spec-mandated per-category
        // counts separately. Bump the literal when adding/removing questions.
        let bank = QuestionBank::parse(BUNDLED_QUESTIONS_YAML).unwrap();
        assert_eq!(bank.version, 1);
        assert_eq!(
            bank.questions.len(),
            23,
            "shipped question count must match the per-category sum (4+6+3+3+4+3)",
        );
        // Every question has both EN and DE prompts.
        for q in &bank.questions {
            assert!(!q.prompt.en.is_empty(), "{} missing en prompt", q.id);
            assert!(!q.prompt.de.is_empty(), "{} missing de prompt", q.id);
        }
    }

    #[test]
    fn bundled_yaml_covers_every_required_category() {
        let bank = QuestionBank::parse(BUNDLED_QUESTIONS_YAML).unwrap();
        let mut counts = std::collections::HashMap::<&str, usize>::new();
        for q in &bank.questions {
            *counts.entry(q.category.as_str()).or_insert(0) += 1;
        }
        // Per memory/neoth_gt_onboarding_pins.md.
        assert_eq!(counts.get("identity").copied(), Some(4));
        assert_eq!(counts.get("hardware").copied(), Some(6));
        assert_eq!(counts.get("routine").copied(), Some(3));
        assert_eq!(counts.get("preferences").copied(), Some(3));
        assert_eq!(counts.get("hard_rules").copied(), Some(4));
        assert_eq!(counts.get("people").copied(), Some(3));
    }

    #[test]
    fn pick_prompt_returns_german_for_de_locale() {
        let p = BilingualPrompt {
            en: "What's your name?".into(),
            de: "Wie heißt du?".into(),
        };
        assert_eq!(pick_prompt(&p, "de"), "Wie heißt du?");
        assert_eq!(pick_prompt(&p, "de-AT"), "Wie heißt du?");
        assert_eq!(pick_prompt(&p, "en"), "What's your name?");
        // Unsupported locale falls back to English.
        assert_eq!(pick_prompt(&p, "fr"), "What's your name?");
    }

    #[test]
    fn statement_for_strips_trailing_question_mark() {
        let s = statement_for("What's your name?", "Sam");
        assert_eq!(s, "What's your name: Sam");
    }

    #[test]
    fn persist_answers_writes_to_db_and_skips_empties() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("v.db");
        let bank = QuestionBank::parse(BUNDLED_QUESTIONS_YAML).unwrap();
        let answers = vec![
            Answer {
                question_id: "name-handle".into(),
                category: "identity".into(),
                scope: "global".into(),
                value: Some("Sam".into()),
            },
            Answer {
                question_id: "role".into(),
                category: "identity".into(),
                scope: "global".into(),
                value: Some("developer".into()),
            },
            Answer {
                question_id: "age-range".into(),
                category: "identity".into(),
                scope: "global".into(),
                value: None, // skipped
            },
        ];
        let n = persist_answers(&db, &bank, &answers, "en", 1_700_000_000_000_000_000).unwrap();
        assert_eq!(n, 2);

        let conn = store::open(&db).unwrap();
        let count = groundtruth::count_active(&conn).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn parse_rejects_unsupported_version() {
        let r = QuestionBank::parse("version: 2\nquestions: []\n");
        assert!(r.is_err());
    }
}
