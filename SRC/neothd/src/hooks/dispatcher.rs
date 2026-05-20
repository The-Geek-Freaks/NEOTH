//! Run hooks at a given stage — Phase 29 R-15 H-3.
//!
//! The dispatcher takes the loaded hook set, walks the subset that matches
//! the current stage, applies each in order, and returns a [`StageOutcome`]
//! that the caller folds into its own dispatch logic.

use anyhow::Result;
use regex::Regex;

use super::schema::{HookAction, HookDef};
use super::stages::HookStage;

/// What the dispatcher decided after running every applicable hook.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StageOutcome {
    /// Pipeline continues. Body is the (possibly replaced) text.
    Continue { body: String, hits: Vec<String> },
    /// Pipeline stops. `reason` is the operator-visible explanation,
    /// `name` is the hook that blocked. Callers usually drop the turn.
    Block { name: String, reason: String },
}

/// Apply every hook for `stage` to `body` in declaration order.
///
/// Replace-actions update the body and the next hook sees the updated
/// text. The first Block wins — later hooks at the same stage do not run.
/// Regex compile errors on a single hook log + skip that hook but do not
/// abort the stage.
pub fn run_stage(stage: HookStage, body: &str, hooks: &[HookDef]) -> Result<StageOutcome> {
    let mut current = body.to_string();
    let mut hits = Vec::new();

    for hook in hooks.iter().filter(|h| h.stage == stage && h.is_enabled()) {
        let fires = match &hook.matcher {
            None => true,
            Some(m) => match Regex::new(&m.pattern) {
                Ok(re) => re.is_match(&current),
                Err(e) => {
                    tracing::warn!(
                        hook = %hook.name,
                        pattern = %m.pattern,
                        error = %e,
                        "bad regex in hook matcher — skipping hook",
                    );
                    continue;
                }
            },
        };
        if !fires {
            continue;
        }
        match &hook.action {
            HookAction::Allow => {
                hits.push(hook.name.clone());
            }
            HookAction::Replace { template } => {
                hits.push(hook.name.clone());
                if let Some(m) = &hook.matcher {
                    if let Ok(re) = Regex::new(&m.pattern) {
                        current = re.replace_all(&current, template.as_str()).into_owned();
                        continue;
                    }
                }
                // No matcher → replace the entire body.
                current = template.clone();
            }
            HookAction::Block { reason } => {
                return Ok(StageOutcome::Block {
                    name: hook.name.clone(),
                    reason: reason.clone(),
                });
            }
        }
    }

    Ok(StageOutcome::Continue {
        body: current,
        hits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::schema::{HookAction, HookMatcher};

    fn allow_hook(name: &str, stage: HookStage) -> HookDef {
        HookDef {
            name: name.into(),
            stage,
            enabled: Some(true),
            matcher: None,
            action: HookAction::Allow,
        }
    }

    fn replace_hook(name: &str, stage: HookStage, pattern: &str, template: &str) -> HookDef {
        HookDef {
            name: name.into(),
            stage,
            enabled: Some(true),
            matcher: Some(HookMatcher {
                pattern: pattern.into(),
            }),
            action: HookAction::Replace {
                template: template.into(),
            },
        }
    }

    fn block_hook(name: &str, stage: HookStage, reason: &str) -> HookDef {
        HookDef {
            name: name.into(),
            stage,
            enabled: Some(true),
            matcher: None,
            action: HookAction::Block {
                reason: reason.into(),
            },
        }
    }

    #[test]
    fn no_hooks_returns_continue_with_unchanged_body() {
        let out = run_stage(HookStage::PreProviderCall, "hi", &[]).unwrap();
        match out {
            StageOutcome::Continue { body, hits } => {
                assert_eq!(body, "hi");
                assert!(hits.is_empty());
            }
            _ => panic!("expected Continue"),
        }
    }

    #[test]
    fn only_hooks_at_matching_stage_run() {
        let hooks = vec![
            allow_hook("a", HookStage::PreProviderCall),
            allow_hook("b", HookStage::PostProviderCall),
        ];
        let out = run_stage(HookStage::PreProviderCall, "x", &hooks).unwrap();
        match out {
            StageOutcome::Continue { hits, .. } => assert_eq!(hits, vec!["a"]),
            _ => panic!("expected Continue"),
        }
    }

    #[test]
    fn replace_hook_mutates_body() {
        let hooks = vec![replace_hook(
            "redact",
            HookStage::PreProviderCall,
            r"secret=\S+",
            "[X]",
        )];
        let out = run_stage(HookStage::PreProviderCall, "hello secret=abc world", &hooks).unwrap();
        match out {
            StageOutcome::Continue { body, hits } => {
                assert_eq!(body, "hello [X] world");
                assert_eq!(hits, vec!["redact"]);
            }
            _ => panic!("expected Continue"),
        }
    }

    #[test]
    fn replace_without_matcher_replaces_entire_body() {
        let hooks = vec![HookDef {
            name: "wipe".into(),
            stage: HookStage::PreProviderCall,
            enabled: Some(true),
            matcher: None,
            action: HookAction::Replace {
                template: "n/a".into(),
            },
        }];
        let out = run_stage(HookStage::PreProviderCall, "anything", &hooks).unwrap();
        match out {
            StageOutcome::Continue { body, .. } => assert_eq!(body, "n/a"),
            _ => panic!("expected Continue"),
        }
    }

    #[test]
    fn block_hook_short_circuits_later_hooks() {
        let hooks = vec![
            block_hook("nope", HookStage::PreProviderCall, "no"),
            allow_hook("never", HookStage::PreProviderCall),
        ];
        let out = run_stage(HookStage::PreProviderCall, "x", &hooks).unwrap();
        match out {
            StageOutcome::Block { name, reason } => {
                assert_eq!(name, "nope");
                assert_eq!(reason, "no");
            }
            _ => panic!("expected Block"),
        }
    }

    #[test]
    fn bad_regex_hook_is_skipped_not_fatal() {
        let bad = HookDef {
            name: "bad".into(),
            stage: HookStage::PreProviderCall,
            enabled: Some(true),
            matcher: Some(HookMatcher {
                pattern: "[invalid".into(),
            }),
            action: HookAction::Block { reason: "x".into() },
        };
        let good = allow_hook("good", HookStage::PreProviderCall);
        let out = run_stage(HookStage::PreProviderCall, "x", &[bad, good]).unwrap();
        match out {
            StageOutcome::Continue { hits, .. } => assert_eq!(hits, vec!["good"]),
            _ => panic!("bad-regex hook must skip, good hook must run"),
        }
    }

    #[test]
    fn chained_replaces_compound() {
        let hooks = vec![
            replace_hook("step1", HookStage::PreProviderCall, "foo", "bar"),
            replace_hook("step2", HookStage::PreProviderCall, "bar", "baz"),
        ];
        let out = run_stage(HookStage::PreProviderCall, "foo", &hooks).unwrap();
        match out {
            StageOutcome::Continue { body, hits } => {
                assert_eq!(body, "baz");
                assert_eq!(hits, vec!["step1", "step2"]);
            }
            _ => panic!("expected Continue"),
        }
    }

    #[test]
    fn disabled_hook_is_skipped() {
        let mut h = allow_hook("off", HookStage::PreProviderCall);
        h.enabled = Some(false);
        let out = run_stage(HookStage::PreProviderCall, "x", &[h]).unwrap();
        match out {
            StageOutcome::Continue { hits, .. } => assert!(hits.is_empty()),
            _ => panic!("expected Continue"),
        }
    }
}
