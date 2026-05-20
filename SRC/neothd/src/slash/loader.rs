//! Load slash commands from `~/.neoth/commands/*.toml` and merge with the
//! built-in set.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use tracing::warn;

use super::builtins::built_in_commands;
use super::schema::SlashCommand;

/// Walk `dir` for `*.toml` files, parse each one, and return the merged
/// set keyed by name. Built-ins are returned even when `dir` is missing.
/// Operator-defined commands with the same name as a built-in win.
///
/// Disabled commands (`enabled = false`) are dropped at load time so
/// downstream dispatch doesn't have to recheck.
pub async fn load_all(dir: &Path) -> Result<Vec<SlashCommand>> {
    let mut by_name: HashMap<String, SlashCommand> = HashMap::new();
    for cmd in built_in_commands() {
        by_name.insert(cmd.name.clone(), cmd);
    }

    if dir.is_dir() {
        let mut rd = tokio::fs::read_dir(dir)
            .await
            .with_context(|| format!("read slash dir {}", dir.display()))?;
        while let Some(entry) = rd.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            match parse_file(&path).await {
                Ok(cmd) => {
                    by_name.insert(cmd.name.clone(), cmd);
                }
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "skipping bad slash command file");
                }
            }
        }
    }

    let mut out: Vec<SlashCommand> = by_name.into_values().filter(|c| c.enabled).collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

async fn parse_file(path: &Path) -> Result<SlashCommand> {
    let body = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("read slash command at {}", path.display()))?;
    let cmd: SlashCommand =
        toml::from_str(&body).with_context(|| format!("parse TOML at {}", path.display()))?;
    if cmd.name.trim().is_empty() {
        anyhow::bail!("slash command at {} has empty name", path.display());
    }
    Ok(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn returns_only_built_ins_when_dir_missing() {
        let dir = tempdir().unwrap();
        let cmds = load_all(&dir.path().join("nope")).await.unwrap();
        let names: Vec<&str> = cmds.iter().map(|c| c.name.as_str()).collect();
        // Legacy prompt-based built-ins.
        assert!(names.contains(&"help"));
        assert!(names.contains(&"recall"));
        assert!(names.contains(&"rollback"));
        assert!(names.contains(&"critic"));
        // Session 15 Pick #30 action-based built-ins.
        assert!(names.contains(&"wizard"));
        assert!(names.contains(&"config"));
        assert!(names.contains(&"provider"));
        assert!(names.contains(&"connect"));
        assert_eq!(
            cmds.len(),
            18,
            "ships 6 prompt-based + 12 action-based built-ins: {names:?}"
        );
    }

    #[tokio::test]
    async fn loads_operator_command_alongside_built_ins() {
        let dir = tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("echo.toml"),
            r#"
name = "echo"
description = "Echo what you said"
prompt = "Repeat back: {args}"
"#,
        )
        .await
        .unwrap();

        let cmds = load_all(dir.path()).await.unwrap();
        assert!(cmds.iter().any(|c| c.name == "echo"));
        // Built-ins still there.
        assert!(cmds.iter().any(|c| c.name == "help"));
    }

    #[tokio::test]
    async fn operator_override_wins_over_built_in() {
        let dir = tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("help.toml"),
            r#"
name = "help"
description = "OPERATOR-CUSTOM HELP"
prompt = "Operator override"
"#,
        )
        .await
        .unwrap();

        let cmds = load_all(dir.path()).await.unwrap();
        let help = cmds.iter().find(|c| c.name == "help").unwrap();
        assert_eq!(help.description, "OPERATOR-CUSTOM HELP");
    }

    #[tokio::test]
    async fn disabled_command_is_dropped_from_loaded_set() {
        let dir = tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("status.toml"),
            r#"
name = "status"
description = "Disabled by operator"
prompt = "n/a"
enabled = false
"#,
        )
        .await
        .unwrap();

        let cmds = load_all(dir.path()).await.unwrap();
        assert!(
            !cmds.iter().any(|c| c.name == "status"),
            "disabled overrides must hide the built-in too",
        );
    }

    #[tokio::test]
    async fn bad_toml_does_not_crash_the_loader() {
        let dir = tempdir().unwrap();
        tokio::fs::write(dir.path().join("broken.toml"), "this = is not [valid")
            .await
            .unwrap();
        let cmds = load_all(dir.path()).await.unwrap();
        // Built-ins still loaded.
        assert!(cmds.iter().any(|c| c.name == "help"));
    }

    #[tokio::test]
    async fn output_is_alphabetical_by_name() {
        let dir = tempdir().unwrap();
        let cmds = load_all(dir.path()).await.unwrap();
        let names: Vec<&str> = cmds.iter().map(|c| c.name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }
}
