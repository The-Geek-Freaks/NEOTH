//! GOLD-ADOPT-16 — parameter resolution + `{{key}}` substitution.
//!
//! Turns a parsed [`RecipeSpec`] + the operator's `--param k=v` values into a
//! [`RenderedRecipe`] (the concrete prompt/system/settings to feed `neoth
//! chat`). Resolution order per parameter: supplied value → declared `default`
//! → error if `required`. Each value is type-checked against its `input_type`
//! before substitution, so a recipe can't smuggle a non-number into a number
//! slot. Substitution is the proven hand-rolled `{{key}}` replace (also accepts
//! `{{ key }}` with inner spaces); a leftover token after substitution is an
//! error (catches a prompt that references an undeclared parameter).

use std::collections::BTreeMap;

use super::schema::{InputType, RecipeError, RecipeParameter, RecipeSettings, RecipeSpec};

/// The concrete, ready-to-run output of rendering a recipe.
#[derive(Clone, Debug, PartialEq)]
pub struct RenderedRecipe {
    /// Substituted user-turn prompt (→ `ChatArgs.message`). Never empty.
    pub prompt: String,
    /// Substituted system override (→ `ChatArgs.system`), if the recipe set one.
    pub system: Option<String>,
    /// Provider/sampling overrides carried through verbatim.
    pub settings: RecipeSettings,
}

/// Validate the supplied params against the spec, resolve defaults, type-check,
/// and substitute. `supplied` is the operator's `k=v` map.
pub fn render(spec: &RecipeSpec, supplied: &BTreeMap<String, String>) -> Result<RenderedRecipe, RecipeError> {
    spec.validate_structure()?;

    // Resolve + type-check each declared parameter into the substitution map.
    let mut values: BTreeMap<String, String> = BTreeMap::new();
    for p in &spec.parameters {
        let raw = match supplied.get(&p.key).cloned().or_else(|| p.default.clone()) {
            Some(v) => v,
            None => {
                if p.required {
                    return Err(RecipeError::MissingRequired(p.key.clone()));
                }
                // Optional + no value + no default → substitutes to empty.
                String::new()
            }
        };
        let checked = type_check(p, &raw)?;
        values.insert(p.key.clone(), checked);
    }
    // Pass through any supplied keys that are NOT declared parameters — these are
    // sub-recipe template injections (`sub_recipes[].key`) the runner merged in,
    // or operator-supplied extras. They substitute as-is (no type-check; their
    // declared owner already validated them). A declared param always wins.
    for (k, v) in supplied {
        values.entry(k.clone()).or_insert_with(|| v.clone());
    }

    let prompt = substitute(&spec.prompt, &values);
    reject_unresolved(&prompt)?;
    if prompt.trim().is_empty() {
        return Err(RecipeError::EmptyPrompt);
    }

    let system = match &spec.instructions {
        Some(instr) => {
            let s = substitute(instr, &values);
            reject_unresolved(&s)?;
            Some(s)
        }
        None => None,
    };

    Ok(RenderedRecipe {
        prompt,
        system,
        settings: spec.settings.clone(),
    })
}

/// Validate `raw` against the parameter's `input_type`, returning the canonical
/// string to substitute (booleans normalise to `true`/`false`).
fn type_check(p: &RecipeParameter, raw: &str) -> Result<String, RecipeError> {
    let v = raw.trim();
    match p.input_type {
        InputType::String => Ok(raw.to_string()),
        InputType::Number => {
            if v.parse::<i64>().is_ok() || v.parse::<f64>().is_ok() {
                Ok(v.to_string())
            } else {
                Err(RecipeError::BadNumber(p.key.clone(), raw.to_string()))
            }
        }
        InputType::Boolean => match v.to_ascii_lowercase().as_str() {
            "true" | "yes" | "1" => Ok("true".to_string()),
            "false" | "no" | "0" => Ok("false".to_string()),
            _ => Err(RecipeError::BadBoolean(p.key.clone(), raw.to_string())),
        },
        InputType::Select => {
            if p.options.iter().any(|o| o == v) {
                Ok(v.to_string())
            } else {
                Err(RecipeError::BadSelect(
                    p.key.clone(),
                    raw.to_string(),
                    p.options.clone(),
                ))
            }
        }
    }
}

/// Replace `{{key}}` and `{{ key }}` (inner spaces tolerated) for every value.
fn substitute(template: &str, values: &BTreeMap<String, String>) -> String {
    let mut out = template.to_string();
    for (k, v) in values {
        out = out.replace(&format!("{{{{{k}}}}}"), v); // {{key}}
        out = out.replace(&format!("{{{{ {k} }}}}"), v); // {{ key }}
    }
    out
}

/// Error if a `{{ identifier }}` token survives substitution — that means the
/// prompt references a parameter the recipe never declared (a typo). Non-token
/// braces (e.g. a JSON example `{{...}}` with non-identifier content) are left
/// alone.
fn reject_unresolved(rendered: &str) -> Result<(), RecipeError> {
    if let Some(start) = rendered.find("{{") {
        let rest = &rendered[start + 2..];
        if let Some(end) = rest.find("}}") {
            let inner = rest[..end].trim();
            // Only treat it as an unresolved PARAM token if it looks like a bare
            // identifier (letters/digits/_/-, no spaces) — avoids false-positives
            // on legit `{{` in example payloads.
            if !inner.is_empty()
                && inner
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return Err(RecipeError::UnresolvedToken(inner.to_string()));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn renders_required_param() {
        let spec = RecipeSpec::parse("name: g\nprompt: \"Hi {{who}}!\"\nparameters:\n  - key: who\n").unwrap();
        let r = render(&spec, &params(&[("who", "Alex")])).unwrap();
        assert_eq!(r.prompt, "Hi Alex!");
    }

    #[test]
    fn missing_required_errors() {
        let spec = RecipeSpec::parse("name: g\nprompt: \"{{who}}\"\nparameters:\n  - key: who\n").unwrap();
        assert_eq!(
            render(&spec, &params(&[])).unwrap_err(),
            RecipeError::MissingRequired("who".into())
        );
    }

    #[test]
    fn default_fills_optional() {
        let spec = RecipeSpec::parse(
            "name: g\nprompt: \"depth {{d}}\"\nparameters:\n  - key: d\n    required: false\n    default: \"3\"\n",
        )
        .unwrap();
        assert_eq!(render(&spec, &params(&[])).unwrap().prompt, "depth 3");
        assert_eq!(render(&spec, &params(&[("d", "9")])).unwrap().prompt, "depth 9");
    }

    #[test]
    fn number_type_is_enforced() {
        let spec = RecipeSpec::parse(
            "name: g\nprompt: \"{{n}}\"\nparameters:\n  - key: n\n    input_type: number\n",
        )
        .unwrap();
        assert!(render(&spec, &params(&[("n", "42")])).is_ok());
        assert_eq!(
            render(&spec, &params(&[("n", "abc")])).unwrap_err(),
            RecipeError::BadNumber("n".into(), "abc".into())
        );
    }

    #[test]
    fn boolean_normalises() {
        let spec = RecipeSpec::parse(
            "name: g\nprompt: \"{{b}}\"\nparameters:\n  - key: b\n    input_type: boolean\n",
        )
        .unwrap();
        assert_eq!(render(&spec, &params(&[("b", "YES")])).unwrap().prompt, "true");
        assert_eq!(render(&spec, &params(&[("b", "0")])).unwrap().prompt, "false");
        assert!(render(&spec, &params(&[("b", "maybe")])).is_err());
    }

    #[test]
    fn select_is_constrained() {
        let spec = RecipeSpec::parse(
            "name: g\nprompt: \"{{m}}\"\nparameters:\n  - key: m\n    input_type: select\n    options: [fast, thorough]\n",
        )
        .unwrap();
        assert_eq!(render(&spec, &params(&[("m", "fast")])).unwrap().prompt, "fast");
        assert!(matches!(
            render(&spec, &params(&[("m", "medium")])).unwrap_err(),
            RecipeError::BadSelect(..)
        ));
    }

    #[test]
    fn instructions_are_substituted_into_system() {
        let spec = RecipeSpec::parse(
            "name: g\nprompt: \"go {{t}}\"\ninstructions: \"You are a {{t}} agent.\"\nparameters:\n  - key: t\n",
        )
        .unwrap();
        let r = render(&spec, &params(&[("t", "fast")])).unwrap();
        assert_eq!(r.prompt, "go fast");
        assert_eq!(r.system.as_deref(), Some("You are a fast agent."));
    }

    #[test]
    fn spaced_token_form_substitutes() {
        let spec = RecipeSpec::parse("name: g\nprompt: \"Hi {{ who }}!\"\nparameters:\n  - key: who\n").unwrap();
        assert_eq!(render(&spec, &params(&[("who", "Bob")])).unwrap().prompt, "Hi Bob!");
    }

    #[test]
    fn undeclared_token_is_rejected() {
        // `{{target}}` is referenced but never declared as a parameter.
        let spec = RecipeSpec::parse("name: g\nprompt: \"scan {{target}}\"\n").unwrap();
        assert_eq!(
            render(&spec, &params(&[])).unwrap_err(),
            RecipeError::UnresolvedToken("target".into())
        );
    }
}
