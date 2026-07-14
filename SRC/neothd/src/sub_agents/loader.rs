//! Load operator-defined sub-agents from `~/.neoth/agents/*.toml` and
//! merge with the built-in set.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use tracing::warn;

use super::builtins::built_in_agents;
use super::schema::SubAgent;

/// Walk `dir` for `*.toml`, parse each, merge with built-ins. Operator
/// entries win on name collision. Disabled entries are dropped. Output
/// is alphabetical by name. Bad TOML logs + skips.
pub async fn load_all(dir: &Path) -> Result<Vec<SubAgent>> {
    let mut by_name: HashMap<String, SubAgent> = HashMap::new();
    for a in built_in_agents() {
        by_name.insert(a.name.clone(), a);
    }

    for agent in load_operator_definitions(dir).await? {
        by_name.insert(agent.name.clone(), agent);
    }

    let mut out: Vec<SubAgent> = by_name.into_values().filter(|a| a.enabled).collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Load only operator TOML definitions, retaining disabled entries. The
/// operator-facing CLI uses this to report provenance accurately; `load_all`
/// then applies the override + enabled filter for dispatch.
pub async fn load_operator_definitions(dir: &Path) -> Result<Vec<SubAgent>> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut rd = tokio::fs::read_dir(dir)
        .await
        .with_context(|| format!("read agents dir {}", dir.display()))?;
    while let Some(entry) = rd.next_entry().await? {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        match parse_file(&path).await {
            Ok(agent) => out.push(agent),
            Err(error) => warn!(
                path = %path.display(),
                error = %error,
                "skipping bad sub-agent file"
            ),
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

async fn parse_file(path: &Path) -> Result<SubAgent> {
    let body = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("read sub-agent at {}", path.display()))?;
    let a: SubAgent =
        toml::from_str(&body).with_context(|| format!("parse TOML at {}", path.display()))?;
    if a.name.trim().is_empty() {
        anyhow::bail!("sub-agent at {} has empty name", path.display());
    }
    if a.system.trim().is_empty() {
        anyhow::bail!(
            "sub-agent {} at {} has empty system prompt",
            a.name,
            path.display()
        );
    }
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn missing_dir_returns_built_ins_only() {
        let dir = tempdir().unwrap();
        let agents = load_all(&dir.path().join("nope")).await.unwrap();
        let names: Vec<&str> = agents.iter().map(|a| a.name.as_str()).collect();
        assert!(names.contains(&"code-reviewer"));
        assert!(names.contains(&"security-reviewer"));
        assert!(names.contains(&"planner"));
        assert!(names.contains(&"critic"));
        assert!(names.contains(&"session-summarizer"));
        assert!(names.contains(&"evidence-collector"));
        assert!(names.contains(&"reality-checker"));
        // Built-ins now number 18 (the original 7 + QU-09b's 11
        // agency-agents personas). Kept in lockstep with builtins.rs's
        // own `built_ins_include_all_eighteen`.
        assert_eq!(agents.len(), 18);
    }

    #[tokio::test]
    async fn operator_can_override_built_in() {
        let dir = tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("planner.toml"),
            r#"
name = "planner"
description = "OPERATOR PLANNER"
system = "do my style"
"#,
        )
        .await
        .unwrap();
        let agents = load_all(dir.path()).await.unwrap();
        let p = agents.iter().find(|a| a.name == "planner").unwrap();
        assert_eq!(p.description, "OPERATOR PLANNER");
    }

    #[tokio::test]
    async fn disabled_override_hides_built_in_too() {
        let dir = tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("code-reviewer.toml"),
            r#"
name = "code-reviewer"
description = "off"
system = "n/a"
enabled = false
"#,
        )
        .await
        .unwrap();
        let agents = load_all(dir.path()).await.unwrap();
        assert!(!agents.iter().any(|a| a.name == "code-reviewer"));
    }

    #[tokio::test]
    async fn operator_can_add_new_agent() {
        let dir = tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("docs.toml"),
            r#"
name = "doc-writer"
description = "Write docs"
system = "You write docs"
"#,
        )
        .await
        .unwrap();
        let agents = load_all(dir.path()).await.unwrap();
        // 18 built-ins (original 7 + QU-09b's 11 agency personas) + 1
        // operator-new = 19.
        assert_eq!(agents.len(), 19);
        assert!(agents.iter().any(|a| a.name == "doc-writer"));
    }

    #[tokio::test]
    async fn empty_system_prompt_fails_parse() {
        let dir = tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("bad.toml"),
            r#"
name = "bad"
description = "Has no system prompt"
system = ""
"#,
        )
        .await
        .unwrap();
        let agents = load_all(dir.path()).await.unwrap();
        // Validation drops the bad one but all 18 built-ins still load.
        assert!(!agents.iter().any(|a| a.name == "bad"));
        // The bad one is dropped by validation; all 18 built-ins remain.
        assert_eq!(agents.len(), 18);
    }
}
