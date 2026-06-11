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

    let (prompt, unresolved) = substitute(&spec.prompt, &values);
    if let Some(tok) = unresolved.into_iter().next() {
        return Err(RecipeError::UnresolvedToken(tok));
    }
    if prompt.trim().is_empty() {
        return Err(RecipeError::EmptyPrompt);
    }

    let system = match &spec.instructions {
        Some(instr) => {
            let (s, unresolved) = substitute(instr, &values);
            if let Some(tok) = unresolved.into_iter().next() {
                return Err(RecipeError::UnresolvedToken(tok));
            }
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

/// Replace `{{key}}` / `{{ key }}` (inner spaces tolerated) in a SINGLE pass,
/// returning the rendered text PLUS the identifier-shaped tokens that referenced
/// an UNDECLARED parameter (a typo).
///
/// GR-116 — a substituted value is emitted VERBATIM and never rescanned, so a
/// value of `{{otherkey}}` can't inject another parameter's placeholder (the old
/// sequential `out.replace(...)` per BTreeMap entry expanded it when that later
/// key's turn arrived — a value-driven template injection).
///
/// GR-115 — every `{{…}}` in the TEMPLATE is inspected (not just the first), and
/// unresolved detection runs HERE on the template tokens, not on the
/// post-substitution string. That means a value which legitimately contains a
/// literal `{{…}}` is never re-examined and so never mistaken for an unresolved
/// reference, while a real undeclared token after a non-identifier `{{…}}` (e.g.
/// a JSON example) is still caught. Non-identifier braces are left literal and
/// never flagged.
fn substitute(template: &str, values: &BTreeMap<String, String>) -> (String, Vec<String>) {
    let mut out = String::with_capacity(template.len());
    let mut unresolved: Vec<String> = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else {
            // No closing brace — emit the remainder verbatim and stop.
            out.push_str(&rest[open..]);
            return (out, unresolved);
        };
        let key = after[..close].trim();
        if let Some(v) = values.get(key) {
            out.push_str(v); // verbatim — never rescanned (GR-116)
        } else {
            // Undeclared token. Flag it iff it's a bare identifier (a typo'd
            // param ref); non-identifier braces (JSON, etc.) are legit literals.
            // Emit verbatim either way.
            if !key.is_empty()
                && key
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                unresolved.push(key.to_string());
            }
            out.push_str(&rest[open..open + 2 + close + 2]);
        }
        rest = &after[close + 2..];
    }
    out.push_str(rest);
    (out, unresolved)
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

    #[test]
    fn value_with_placeholder_is_not_re_expanded_gr116() {
        // GR-116 — a's value contains `{{b}}`; the single-pass substitute must
        // emit it VERBATIM, NOT expand it when b's turn comes.
        let spec = RecipeSpec::parse(
            "name: g\nprompt: \"{{a}}-{{b}}\"\nparameters:\n  - key: a\n  - key: b\n",
        )
        .unwrap();
        let r = render(&spec, &params(&[("a", "{{b}}"), ("b", "X")])).unwrap();
        assert_eq!(r.prompt, "{{b}}-X", "a's value must stay literal, not become X-X");
    }

    #[test]
    fn unresolved_token_after_non_identifier_braces_is_caught_gr115() {
        // GR-115 — the first `{{x y}}` is non-identifier (space) and skipped; a
        // REAL undeclared `{{target}}` later in the string must still be caught
        // (the old code only inspected the first `{{`).
        let spec = RecipeSpec::parse("name: g\nprompt: \"a {{x y}} b {{target}}\"\n").unwrap();
        assert_eq!(
            render(&spec, &params(&[])).unwrap_err(),
            RecipeError::UnresolvedToken("target".into())
        );
    }
}
