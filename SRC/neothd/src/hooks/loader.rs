//! Load operator-defined hooks from `~/.neoth/hooks/*.toml`.

use std::path::Path;

use anyhow::{Context, Result};
use tracing::warn;

use super::schema::HookDef;

/// Walk `dir` for `*.toml` files, parse each one, and return enabled
/// hooks sorted by name. Bad TOML is logged + skipped — a single corrupt
/// file must not block the rest.
///
/// Returns an empty list when `dir` does not exist (operator hasn't
/// created any hooks yet).
pub async fn load_all(dir: &Path) -> Result<Vec<HookDef>> {
    let mut out = Vec::new();
    if !dir.is_dir() {
        return Ok(out);
    }
    let mut rd = tokio::fs::read_dir(dir)
        .await
        .with_context(|| format!("read hooks dir {}", dir.display()))?;
    while let Some(entry) = rd.next_entry().await? {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        match parse_file(&path).await {
            Ok(h) if h.is_enabled() => out.push(h),
            Ok(_) => {} // disabled — drop silently
            Err(e) => warn!(path = %path.display(), error = %e, "skipping bad hook file"),
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

async fn parse_file(path: &Path) -> Result<HookDef> {
    let body = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("read hook at {}", path.display()))?;
    let h: HookDef =
        toml::from_str(&body).with_context(|| format!("parse TOML at {}", path.display()))?;
    if h.name.trim().is_empty() {
        anyhow::bail!("hook at {} has empty name", path.display());
    }
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn missing_dir_returns_empty() {
        let dir = tempdir().unwrap();
        let hooks = load_all(&dir.path().join("absent")).await.unwrap();
        assert!(hooks.is_empty());
    }

    #[tokio::test]
    async fn loads_one_hook_and_skips_non_toml() {
        let dir = tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("redact.toml"),
            r#"
name = "redact"
stage = "pre_provider_call"
[matcher]
pattern = "secret=\\S+"
[action]
kind = "replace"
template = "[X]"
"#,
        )
        .await
        .unwrap();
        tokio::fs::write(dir.path().join("ignore.md"), "not a hook")
            .await
            .unwrap();

        let hooks = load_all(dir.path()).await.unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].name, "redact");
    }

    #[tokio::test]
    async fn disabled_hook_dropped() {
        let dir = tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("off.toml"),
            r#"
name = "off"
stage = "pre_pipeline"
enabled = false
[action]
kind = "allow"
"#,
        )
        .await
        .unwrap();
        let hooks = load_all(dir.path()).await.unwrap();
        assert!(hooks.is_empty(), "disabled hooks must be filtered out");
    }

    #[tokio::test]
    async fn bad_toml_does_not_crash_loader() {
        let dir = tempdir().unwrap();
        tokio::fs::write(dir.path().join("broken.toml"), "not = [valid")
            .await
            .unwrap();
        tokio::fs::write(
            dir.path().join("ok.toml"),
            r#"
name = "ok"
stage = "pre_provider_call"
[action]
kind = "allow"
"#,
        )
        .await
        .unwrap();
        let hooks = load_all(dir.path()).await.unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].name, "ok");
    }

    #[tokio::test]
    async fn output_sorted_alphabetically() {
        let dir = tempdir().unwrap();
        for name in ["zebra", "alpha", "mike"] {
            tokio::fs::write(
                dir.path().join(format!("{name}.toml")),
                format!(
                    "name = \"{name}\"\nstage = \"pre_pipeline\"\n[action]\nkind = \"allow\"\n"
                ),
            )
            .await
            .unwrap();
        }
        let hooks = load_all(dir.path()).await.unwrap();
        let names: Vec<&str> = hooks.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "mike", "zebra"]);
    }
}
