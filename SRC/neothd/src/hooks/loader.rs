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
    load_all_with_policy(dir, false).await
}

/// Strict loader for safety-sensitive call sites. Unlike [`load_all`], one
/// unreadable or malformed hook aborts the whole load instead of silently
/// removing an operator-defined policy from the active set.
pub async fn load_all_strict(dir: &Path) -> Result<Vec<HookDef>> {
    load_all_with_policy(dir, true).await
}

async fn load_all_with_policy(dir: &Path, strict: bool) -> Result<Vec<HookDef>> {
    let mut out = Vec::new();
    match tokio::fs::metadata(dir).await {
        Ok(metadata) if !metadata.is_dir() => {
            if strict {
                anyhow::bail!("hooks path {} is not a directory", dir.display());
            }
            return Ok(out);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(error) => {
            return Err(error).with_context(|| format!("inspect hooks dir {}", dir.display()));
        }
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
            Ok(h) => {
                if h.is_enabled() {
                    if strict {
                        validate_strict(&h).with_context(|| {
                            format!("strict hook validation failed at {}", path.display())
                        })?;
                    }
                    out.push(h);
                }
            }
            Err(error) if strict => {
                return Err(error)
                    .with_context(|| format!("strict hook load failed at {}", path.display()));
            }
            Err(error) => {
                warn!(path = %path.display(), error = %error, "skipping bad hook file")
            }
        }
    }
    // AR-03 (Session 24) — sort by (priority asc, name asc). Lower
    // priority fires first; alphabetical name is the deterministic
    // tie-breaker so hooks with the same priority still load in a
    // stable order across installs (operator-visible reproducibility).
    // Pre-AR-03 sort was alphabetical-only, forcing operators to
    // smuggle order into filenames.
    out.sort_by(|a, b| {
        a.effective_priority()
            .cmp(&b.effective_priority())
            .then_with(|| a.name.cmp(&b.name))
    });
    Ok(out)
}

/// Validate every fallible runtime matcher for strict policy consumers. This
/// keeps an invalid regex from degrading to the dispatcher's legacy
/// warn-and-continue path after the operator hook set was accepted.
fn validate_strict(hook: &HookDef) -> Result<()> {
    if let Some(matcher) = &hook.matcher {
        regex::Regex::new(&matcher.pattern).with_context(|| {
            format!(
                "hook `{}` has invalid matcher regex `{}`",
                hook.name, matcher.pattern
            )
        })?;
    }
    // GOLD-CCPARITY-ONCE is for startup banners and one-shot plugins. Combined
    // with a blocking action it is a latent fail-OPEN: the hook blocks the first
    // turn, its once-claim is consumed, and every later turn passes the stage
    // through — an operator who wrote a gate gets a gate that stops working
    // after one use, silently. Nothing validated the combination, so refuse it
    // at load: a security-shaped hook must not depend on the operator noticing.
    if hook.once() && matches!(hook.action, crate::hooks::schema::HookAction::Block { .. }) {
        anyhow::bail!(
            "hook `{}` combines `once = true` with a blocking action. A once-hook is consumed \
             after it fires, so the block would stop applying from the second turn on. Drop \
             `once` to keep blocking, or use a non-blocking action.",
            hook.name
        );
    }
    Ok(())
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

    /// External review PR4-036: a once-hook is consumed after it fires, so
    /// pairing it with a blocking action yields a gate that stops gating from
    /// the second turn on — a latent fail-open nothing validated.
    #[tokio::test]
    async fn once_plus_block_is_refused_at_load() {
        let dir = tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("gate.toml"),
            r#"
name = "gate"
stage = "pre_provider_call"
once = true
[action]
kind = "block"
reason = "not allowed"
"#,
        )
        .await
        .unwrap();

        let error = load_all_strict(dir.path())
            .await
            .expect_err("a once-hook that blocks must not load");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("once = true") && rendered.contains("blocking action"),
            "the refusal must name the combination and the fix: {rendered}"
        );

        // The same hook without `once` is a real gate and still loads.
        tokio::fs::write(
            dir.path().join("gate.toml"),
            r#"
name = "gate"
stage = "pre_provider_call"
[action]
kind = "block"
reason = "not allowed"
"#,
        )
        .await
        .unwrap();
        assert_eq!(load_all_strict(dir.path()).await.unwrap().len(), 1);
    }

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
    async fn strict_loader_rejects_bad_toml() {
        let dir = tempdir().unwrap();
        tokio::fs::write(dir.path().join("broken.toml"), "not = [valid")
            .await
            .unwrap();
        let error = load_all_strict(dir.path()).await.unwrap_err();
        assert!(error.to_string().contains("strict hook load failed"));
    }

    #[tokio::test]
    async fn strict_loader_rejects_unreadable_toml_entry() {
        let dir = tempdir().unwrap();
        tokio::fs::create_dir(dir.path().join("unreadable.toml"))
            .await
            .unwrap();
        let error = load_all_strict(dir.path()).await.unwrap_err();
        assert!(error.to_string().contains("strict hook load failed"));
    }

    #[tokio::test]
    async fn strict_loader_rejects_invalid_runtime_regex() {
        let dir = tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("broken-regex.toml"),
            "name = \"broken-regex\"\nstage = \"pre_provider_call\"\n\
             [matcher]\npattern = \"[\"\n\
             [action]\nkind = \"allow\"\n",
        )
        .await
        .unwrap();
        let error = load_all_strict(dir.path()).await.unwrap_err();
        assert!(error.to_string().contains("strict hook validation failed"));
    }

    #[tokio::test]
    async fn output_sorted_alphabetically_when_priority_unset() {
        // AR-03 (Session 24): with no `priority` field set, every hook
        // takes the DEFAULT_PRIORITY and the alphabetical tie-breaker
        // pins the legacy ordering. Catches any regression in the
        // tie-break direction.
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

    #[tokio::test]
    async fn ar_03_priority_field_overrides_alphabetical() {
        // Explicit priorities pull "zebra" ahead of "alpha". Without
        // AR-03 this would fail — the legacy sort would put "alpha"
        // first regardless of priority.
        let dir = tempdir().unwrap();
        let cases = [
            ("zebra", 1),
            ("alpha", 50),
            ("mike", 100),
            ("delta", 100), // ties with mike → broken by alphabetical
        ];
        for (name, prio) in &cases {
            tokio::fs::write(
                dir.path().join(format!("{name}.toml")),
                format!(
                    "name = \"{name}\"\nstage = \"pre_pipeline\"\npriority = {prio}\n\
                     [action]\nkind = \"allow\"\n",
                ),
            )
            .await
            .unwrap();
        }
        let hooks = load_all(dir.path()).await.unwrap();
        let names: Vec<&str> = hooks.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["zebra", "alpha", "delta", "mike"],
            "priority asc + name asc tie-break expected",
        );
    }

    #[tokio::test]
    async fn ar_03_priority_negative_values_load_first() {
        // Useful for safety hooks that MUST fire before anything else
        // (e.g. operator-defined panic kill-switch). Negative values
        // are explicitly supported.
        let dir = tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("kill.toml"),
            "name = \"kill\"\nstage = \"pre_pipeline\"\npriority = -100\n\
             [action]\nkind = \"block\"\nreason = \"panic\"\n",
        )
        .await
        .unwrap();
        tokio::fs::write(
            dir.path().join("normal.toml"),
            "name = \"normal\"\nstage = \"pre_pipeline\"\n[action]\nkind = \"allow\"\n",
        )
        .await
        .unwrap();
        let hooks = load_all(dir.path()).await.unwrap();
        let names: Vec<&str> = hooks.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, vec!["kill", "normal"]);
    }
}
