//! GOLD-ADOPT-16 — declarative recipe schema (ported from goose
//! `crates/goose/src/recipe/`, adapted to NEOTH idioms).
//!
//! A recipe is a YAML template with typed `parameters` and a `{{key}}`-templated
//! `prompt` (+ optional `instructions` system override + `settings`). Running it
//! substitutes the operator's `--param k=v` values into the prompt and feeds the
//! result through the normal `neoth chat` pipeline. Substitution is the same
//! hand-rolled `{{key}}` replace the slash/tweaks renderers already use — no
//! template-engine dependency, since typed parameters are a finite known set
//! (no Jinja conditionals/loops needed for this use case).

use serde::{Deserialize, Serialize};

/// Typed parameter input kinds. Drives validation + (future) prompting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum InputType {
    /// Free text (default).
    #[default]
    String,
    /// Must parse as a number (i64 or f64).
    Number,
    /// `true`/`false` (case-insensitive); also accepts `1`/`0`, `yes`/`no`.
    Boolean,
    /// One of `options` (validated against the allowed set).
    Select,
}

/// One declared recipe parameter.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct RecipeParameter {
    /// The `{{key}}` token this fills.
    pub key: String,
    /// Operator-facing description (used by `validate` + future prompting).
    #[serde(default)]
    pub description: String,
    /// Value kind for validation.
    #[serde(default)]
    pub input_type: InputType,
    /// When `true`, running the recipe without this param is an error (unless a
    /// `default` is present). Default `true` — a parameter is required unless the
    /// recipe author marks it optional.
    #[serde(default = "default_true")]
    pub required: bool,
    /// Value used when the operator does not supply one. Makes a `required`
    /// parameter effectively optional (the default fills it).
    #[serde(default)]
    pub default: Option<String>,
    /// Allowed values for `input_type: select`. Ignored for other types.
    #[serde(default)]
    pub options: Vec<String>,
}

fn default_true() -> bool {
    true
}

/// Per-recipe provider/sampling overrides (the "settings override" the spec
/// names). All optional; absent fields keep the operator's `freedom.yaml`
/// defaults.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct RecipeSettings {
    /// Model id override for this recipe's run (e.g. a cheap model for a
    /// classify recipe). Maps to `ChatArgs.model`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Sampling temperature override. Maps to `ChatArgs.temperature`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
}

/// A reference to another recipe run as a pre-step; its rendered prompt is
/// available to the parent via the `{{key}}` named here once executed.
/// (Composition: parsed + validated here; execution wiring is the runner's.)
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct SubRecipe {
    /// The `{{key}}` the parent prompt uses to reference this sub-recipe's output.
    pub key: String,
    /// Path to the sub-recipe YAML, resolved relative to the parent recipe file.
    pub file: String,
    /// Parameter values passed to the sub-recipe. Values may themselves be
    /// `{{parent_param}}` tokens, substituted from the parent's params first.
    #[serde(default)]
    pub params: std::collections::BTreeMap<String, String>,
}

/// Retry policy: re-run the recipe up to `max` extra times while a shell
/// `success_check` command keeps exiting non-zero. The check runs AFTER each
/// attempt; exit 0 = success = stop. Off when absent.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct RetryPolicy {
    /// Maximum EXTRA attempts after the first (so total runs = max + 1).
    pub max: u32,
    /// Shell command whose exit status decides success (0 = success, stop).
    pub success_check: String,
}

/// A parsed recipe.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct RecipeSpec {
    /// Short name (used in `recipe list` + deeplinks).
    pub name: String,
    /// One-line description.
    #[serde(default)]
    pub description: String,
    /// Declared parameters (typed). Empty = a static recipe.
    #[serde(default)]
    pub parameters: Vec<RecipeParameter>,
    /// Optional system-prompt override template (`{{key}}`-substituted). Maps to
    /// `ChatArgs.system`.
    #[serde(default)]
    pub instructions: Option<String>,
    /// The user-turn prompt template (`{{key}}`-substituted). Required + must be
    /// non-empty after rendering. Maps to `ChatArgs.message`.
    pub prompt: String,
    /// Provider/sampling overrides.
    #[serde(default)]
    pub settings: RecipeSettings,
    /// Sub-recipes run before this one (composition).
    #[serde(default)]
    pub sub_recipes: Vec<SubRecipe>,
    /// Retry policy (shell success-check).
    #[serde(default)]
    pub retry: Option<RetryPolicy>,
}

/// Errors that make a recipe unusable.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RecipeError {
    #[error("recipe YAML parse error: {0}")]
    Parse(String),
    #[error("recipe `prompt` is empty — a recipe must carry a prompt template")]
    EmptyPrompt,
    #[error("duplicate parameter key `{0}` — each parameter key must be unique")]
    DuplicateParam(String),
    #[error("parameter `{0}` is input_type: select but declares no `options`")]
    SelectWithoutOptions(String),
    #[error("parameter `{0}` default `{1}` is not one of its select options")]
    DefaultNotInOptions(String, String),
    #[error("required parameter `{0}` was not supplied (pass --param {0}=<value>)")]
    MissingRequired(String),
    #[error("parameter `{0}` = `{1}` is not a valid number")]
    BadNumber(String, String),
    #[error("parameter `{0}` = `{1}` is not a valid boolean (true/false/yes/no/1/0)")]
    BadBoolean(String, String),
    #[error("parameter `{0}` = `{1}` is not one of its select options {2:?}")]
    BadSelect(String, String, Vec<String>),
    #[error("prompt/instructions still reference an undeclared parameter token `{0}`")]
    UnresolvedToken(String),
}

impl RecipeSpec {
    /// Parse + structurally validate a recipe from YAML text. Catches malformed
    /// shapes (empty prompt, dup keys, select-without-options, bad default)
    /// BEFORE any run — `neoth recipe validate` surfaces exactly these.
    pub fn parse(yaml: &str) -> Result<Self, RecipeError> {
        let spec: RecipeSpec =
            serde_yaml::from_str(yaml).map_err(|e| RecipeError::Parse(e.to_string()))?;
        spec.validate_structure()?;
        Ok(spec)
    }

    /// Structural validation independent of supplied parameter values.
    pub fn validate_structure(&self) -> Result<(), RecipeError> {
        if self.prompt.trim().is_empty() {
            return Err(RecipeError::EmptyPrompt);
        }
        let mut seen = std::collections::HashSet::new();
        for p in &self.parameters {
            if !seen.insert(&p.key) {
                return Err(RecipeError::DuplicateParam(p.key.clone()));
            }
            if p.input_type == InputType::Select {
                if p.options.is_empty() {
                    return Err(RecipeError::SelectWithoutOptions(p.key.clone()));
                }
                if let Some(d) = &p.default {
                    if !p.options.contains(d) {
                        return Err(RecipeError::DefaultNotInOptions(p.key.clone(), d.clone()));
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str =
        "name: greet\nprompt: \"Say hi to {{who}}.\"\nparameters:\n  - key: who\n";

    #[test]
    fn parses_minimal_recipe() {
        let r = RecipeSpec::parse(MINIMAL).unwrap();
        assert_eq!(r.name, "greet");
        assert_eq!(r.parameters.len(), 1);
        assert_eq!(r.parameters[0].key, "who");
        assert!(r.parameters[0].required, "params default to required");
        assert_eq!(r.parameters[0].input_type, InputType::String);
    }

    #[test]
    fn empty_prompt_is_rejected() {
        assert_eq!(
            RecipeSpec::parse("name: x\nprompt: \"   \"\n").unwrap_err(),
            RecipeError::EmptyPrompt
        );
    }

    #[test]
    fn duplicate_param_key_is_rejected() {
        let y = "name: x\nprompt: \"{{a}}\"\nparameters:\n  - key: a\n  - key: a\n";
        assert_eq!(
            RecipeSpec::parse(y).unwrap_err(),
            RecipeError::DuplicateParam("a".into())
        );
    }

    #[test]
    fn select_without_options_is_rejected() {
        let y = "name: x\nprompt: \"{{m}}\"\nparameters:\n  - key: m\n    input_type: select\n";
        assert_eq!(
            RecipeSpec::parse(y).unwrap_err(),
            RecipeError::SelectWithoutOptions("m".into())
        );
    }

    #[test]
    fn select_default_must_be_an_option() {
        let y = "name: x\nprompt: \"{{m}}\"\nparameters:\n  - key: m\n    input_type: select\n    options: [a, b]\n    default: c\n";
        assert_eq!(
            RecipeSpec::parse(y).unwrap_err(),
            RecipeError::DefaultNotInOptions("m".into(), "c".into())
        );
    }

    #[test]
    fn settings_and_retry_round_trip() {
        let y = "name: x\nprompt: \"go\"\nsettings:\n  model: claude-haiku-4-5\n  temperature: 0.2\nretry:\n  max: 2\n  success_check: \"test -f /tmp/done\"\n";
        let r = RecipeSpec::parse(y).unwrap();
        assert_eq!(r.settings.model.as_deref(), Some("claude-haiku-4-5"));
        assert_eq!(r.settings.temperature, Some(0.2));
        assert_eq!(r.retry.as_ref().unwrap().max, 2);
    }
}
