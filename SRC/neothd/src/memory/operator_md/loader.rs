//! Disk → `Vec<MemoryBlock>` loader.
//!
//! Reads in this order, skipping missing files silently:
//!   1. `~/.neoth/NEOTH.md`            (Global)
//!   2. `<cwd>/NEOTH.md`               (Project)
//!   3. `~/.neoth/rules/index.md` + every `*.md` it lists (Rule)
//!   4. `~/.neoth/memory/MEMORY.md` + every `*.md` it references (Memory)
//!   5. Each `extra_dirs` entry / `NEOTH.md`  (SubDir — GOLD-CCPARITY-SUBDIR-MD-01,
//!      mirrors Claude Code's `additionalDirectories`; merged after Project, before Rule)
//!
//! "References" in (3) and (4) = markdown link syntax `[…](path.md)` where
//! `path.md` is resolved relative to the index file's directory. Anything
//! that does not resolve to an existing `*.md` inside the parent tree is
//! ignored (defensive — index files may have stale links).
//!
//! Future hooks (deferred to phase-25 follow-up): TTL on memory entries,
//! frontmatter parsing, semantic re-rank by relevance to current prompt.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::debug;

use super::{BlockSource, MemoryBlock};

/// Assemble all operator-md context blocks. `home` is `~/.neoth/`; `cwd` is
/// the operator's current working directory (for project-scoped overrides).
/// `extra_dirs` is a list of additional directories whose NEOTH.md files are
/// merged into the operator-context block (GOLD-CCPARITY-SUBDIR-MD-01 —
/// mirrors Claude Code's `additionalDirectories`). Paths equal to `home` or
/// `cwd` (by canonical comparison) are silently skipped to prevent
/// double-loading.
///
/// Never errors on missing files. Returns Ok with whatever was found.
pub async fn assemble(home: &Path, cwd: &Path, extra_dirs: &[PathBuf]) -> Result<Vec<MemoryBlock>> {
    let mut blocks: Vec<MemoryBlock> = Vec::new();

    // Build a set of canonical paths already covered by steps 1 + 2, used as
    // the dedup guard for extra_dirs in step 2b. Best-effort: if canonicalize
    // fails (path doesn't exist yet) we skip insertion rather than erroring.
    let mut seen_canonical: HashSet<PathBuf> = HashSet::new();
    if let Ok(c) = std::fs::canonicalize(home) {
        seen_canonical.insert(c);
    }
    if let Ok(c) = std::fs::canonicalize(cwd) {
        seen_canonical.insert(c);
    }

    // 1. Global ~/.neoth/NEOTH.md
    let global = home.join("NEOTH.md");
    if let Some(b) = try_load(&global, BlockSource::Global).await? {
        debug!(path = %global.display(), bytes = b.content.len(), "loaded global NEOTH.md");
        blocks.push(b);
    }

    // 2. Project <cwd>/NEOTH.md (only when cwd is not the home dir — otherwise we double-load)
    if cwd != home {
        let project = cwd.join("NEOTH.md");
        if let Some(b) = try_load(&project, BlockSource::Project).await? {
            debug!(path = %project.display(), bytes = b.content.len(), "loaded project NEOTH.md");
            blocks.push(b);
        }
    }

    // 2b. Sub-directory extra_dirs — GOLD-CCPARITY-SUBDIR-MD-01.
    // For each dir, canonicalize and check against `seen_canonical` to avoid
    // double-loading when the caller passes home or cwd as an extra dir. On
    // Windows, PathBuf::eq is case-sensitive so canonical comparison is the
    // only safe approach.
    for dir in extra_dirs {
        // Canonical check: skip if this dir resolves to the same inode as home
        // or cwd. On error (path doesn't exist) we still attempt the load —
        // try_load returns Ok(None) for missing files, which is correct.
        let is_dupe = std::fs::canonicalize(dir)
            .map(|c| seen_canonical.contains(&c))
            .unwrap_or(false);
        if is_dupe {
            debug!(
                path = %dir.display(),
                "extra_dir equals home or cwd (canonical) — skipping to prevent double-load"
            );
            continue;
        }
        let subdir_md = dir.join("NEOTH.md");
        if let Some(b) = try_load(&subdir_md, BlockSource::SubDir).await? {
            debug!(
                path = %subdir_md.display(),
                bytes = b.content.len(),
                "loaded subdir NEOTH.md (GOLD-CCPARITY-SUBDIR-MD-01)"
            );
            blocks.push(b);
            // Register this dir so a later duplicate extra_dir entry is also
            // skipped (e.g. two extra_dirs that both resolve to the same path).
            if let Ok(c) = std::fs::canonicalize(dir) {
                seen_canonical.insert(c);
            }
        }
    }

    // 3. Rules from ~/.neoth/rules/index.md
    let rules_index = home.join("rules").join("index.md");
    if rules_index.exists() {
        for entry in resolve_index(&rules_index).await? {
            if let Some(b) = try_load(&entry, BlockSource::Rule).await? {
                debug!(path = %entry.display(), bytes = b.content.len(), "loaded rule");
                blocks.push(b);
            }
        }
    }

    // 4. Memories from ~/.neoth/memory/MEMORY.md
    let memory_index = home.join("memory").join("MEMORY.md");
    if memory_index.exists() {
        for entry in resolve_index(&memory_index).await? {
            if let Some(b) = try_load(&entry, BlockSource::Memory).await? {
                debug!(path = %entry.display(), bytes = b.content.len(), "loaded memory");
                blocks.push(b);
            }
        }
    }

    Ok(blocks)
}

/// Read a single `*.md` file. Returns `Ok(None)` if the file does not exist.
async fn try_load(path: &Path, source: BlockSource) -> Result<Option<MemoryBlock>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("read operator-md {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(MemoryBlock {
        source,
        path: path.to_path_buf(),
        content: raw,
    }))
}

/// Parse a markdown index file. Returns the set of `*.md` files it references
/// (via `[label](relative-path.md)` link syntax), resolved against the index
/// file's parent dir. Filters: only paths that already exist and end in `.md`.
async fn resolve_index(index_path: &Path) -> Result<Vec<PathBuf>> {
    let raw = tokio::fs::read_to_string(index_path)
        .await
        .with_context(|| format!("read index {}", index_path.display()))?;
    let parent = index_path.parent().unwrap_or_else(|| Path::new("."));

    let mut found = Vec::new();
    // Cheap markdown-link scan: `](path)` with no embedded `)`. Sufficient
    // for our format (index files are operator-curated).
    let chars = raw.char_indices().peekable();
    for (i, c) in chars {
        if c == ']' && raw[i..].starts_with("](") {
            let after_paren = i + 2;
            if let Some(close) = raw[after_paren..].find(')') {
                let link = &raw[after_paren..after_paren + close];
                // Strip optional title: ](path "title")
                let link = link.split_whitespace().next().unwrap_or(link);
                if link.ends_with(".md") && !link.starts_with("http") {
                    let resolved = parent.join(link);
                    if resolved.exists() {
                        found.push(resolved);
                    }
                }
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::fs;

    /// First-time operator: no NEOTH.md anywhere. Loader returns empty Vec, not error.
    #[tokio::test]
    async fn missing_everything_returns_empty() {
        let dir = tempdir().unwrap();
        let home = dir.path().join(".neoth");
        let cwd = dir.path().join("proj");
        fs::create_dir_all(&home).await.unwrap();
        fs::create_dir_all(&cwd).await.unwrap();
        let blocks = assemble(&home, &cwd, &[]).await.unwrap();
        assert!(blocks.is_empty());
    }

    #[tokio::test]
    async fn loads_global_only_when_no_project_or_index() {
        let dir = tempdir().unwrap();
        let home = dir.path().join(".neoth");
        let cwd = dir.path().join("proj");
        fs::create_dir_all(&home).await.unwrap();
        fs::create_dir_all(&cwd).await.unwrap();
        fs::write(home.join("NEOTH.md"), "# Global rules\nBe blunt.")
            .await
            .unwrap();

        let blocks = assemble(&home, &cwd, &[]).await.unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].source, BlockSource::Global);
        assert!(blocks[0].content.contains("Be blunt"));
    }

    #[tokio::test]
    async fn project_overrides_load_after_global() {
        let dir = tempdir().unwrap();
        let home = dir.path().join(".neoth");
        let cwd = dir.path().join("proj");
        fs::create_dir_all(&home).await.unwrap();
        fs::create_dir_all(&cwd).await.unwrap();
        fs::write(home.join("NEOTH.md"), "Global content")
            .await
            .unwrap();
        fs::write(cwd.join("NEOTH.md"), "Project content")
            .await
            .unwrap();

        let blocks = assemble(&home, &cwd, &[]).await.unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].source, BlockSource::Global);
        assert_eq!(blocks[1].source, BlockSource::Project);
    }

    #[tokio::test]
    async fn rules_index_pulls_referenced_files() {
        let dir = tempdir().unwrap();
        let home = dir.path().join(".neoth");
        let rules = home.join("rules");
        fs::create_dir_all(&rules).await.unwrap();
        fs::write(rules.join("style.md"), "Style rules here")
            .await
            .unwrap();
        fs::write(rules.join("testing.md"), "Testing rules here")
            .await
            .unwrap();
        fs::write(
            rules.join("index.md"),
            "# Rules\n- [Style](style.md)\n- [Testing](testing.md)\n- [Missing](nope.md)\n",
        )
        .await
        .unwrap();

        let blocks = assemble(&home, &home, &[]).await.unwrap();
        // Global NEOTH.md absent; rules x 2; no project (cwd == home).
        assert_eq!(blocks.len(), 2);
        assert!(blocks.iter().all(|b| b.source == BlockSource::Rule));
        let paths: Vec<String> = blocks
            .iter()
            .map(|b| b.path.display().to_string())
            .collect();
        assert!(paths.iter().any(|p| p.ends_with("style.md")));
        assert!(paths.iter().any(|p| p.ends_with("testing.md")));
    }

    #[tokio::test]
    async fn memory_index_pulls_typed_memories() {
        let dir = tempdir().unwrap();
        let home = dir.path().join(".neoth");
        let mem = home.join("memory");
        fs::create_dir_all(&mem).await.unwrap();
        fs::write(mem.join("user.md"), "User: solo dev")
            .await
            .unwrap();
        fs::write(mem.join("project.md"), "Project: NEOTH")
            .await
            .unwrap();
        fs::write(
            mem.join("MEMORY.md"),
            "- [User](user.md)\n- [Project](project.md)\n",
        )
        .await
        .unwrap();

        let blocks = assemble(&home, &home, &[]).await.unwrap();
        assert_eq!(blocks.len(), 2);
        assert!(blocks.iter().all(|b| b.source == BlockSource::Memory));
    }

    #[tokio::test]
    async fn empty_md_file_is_skipped() {
        let dir = tempdir().unwrap();
        let home = dir.path().join(".neoth");
        fs::create_dir_all(&home).await.unwrap();
        fs::write(home.join("NEOTH.md"), "   \n\t\n").await.unwrap();

        let blocks = assemble(&home, &home, &[]).await.unwrap();
        assert!(blocks.is_empty());
    }

    #[tokio::test]
    async fn render_concatenates_with_attribution_headers() {
        let blocks = vec![
            MemoryBlock {
                source: BlockSource::Global,
                path: PathBuf::from("/x/.neoth/NEOTH.md"),
                content: "Global content".to_string(),
            },
            MemoryBlock {
                source: BlockSource::Rule,
                path: PathBuf::from("/x/.neoth/rules/style.md"),
                content: "Style content".to_string(),
            },
        ];
        let rendered = super::super::render(&blocks);
        assert!(rendered.contains("## global:"));
        assert!(rendered.contains("Global content"));
        assert!(rendered.contains("## rule:"));
        assert!(rendered.contains("Style content"));
    }

    #[tokio::test]
    async fn http_links_in_index_are_ignored() {
        let dir = tempdir().unwrap();
        let home = dir.path().join(".neoth");
        let rules = home.join("rules");
        fs::create_dir_all(&rules).await.unwrap();
        fs::write(rules.join("local.md"), "Local rule")
            .await
            .unwrap();
        fs::write(
            rules.join("index.md"),
            "- [external](https://example.com/foo.md)\n- [local](local.md)\n",
        )
        .await
        .unwrap();

        let blocks = assemble(&home, &home, &[]).await.unwrap();
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].path.ends_with("local.md"));
    }

    // ── GOLD-CCPARITY-SUBDIR-MD-01 — extra_dirs integration tests ────────────

    #[tokio::test]
    async fn subdir_extra_dir_neoth_md_is_merged() {
        let dir = tempdir().unwrap();
        let home = dir.path().join(".neoth");
        let cwd = dir.path().join("root");
        let sub = dir.path().join("root/packages/core");
        fs::create_dir_all(&home).await.unwrap();
        fs::create_dir_all(&cwd).await.unwrap();
        fs::create_dir_all(&sub).await.unwrap();
        fs::write(home.join("NEOTH.md"), "Global").await.unwrap();
        fs::write(sub.join("NEOTH.md"), "Sub-project rules")
            .await
            .unwrap();

        let blocks = assemble(&home, &cwd, std::slice::from_ref(&sub))
            .await
            .unwrap();
        // Global + SubDir (cwd/NEOTH.md absent)
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].source, BlockSource::Global);
        assert_eq!(blocks[1].source, BlockSource::SubDir);
        assert!(blocks[1].content.contains("Sub-project rules"));
        assert_eq!(blocks[1].path, sub.join("NEOTH.md"));
    }

    #[tokio::test]
    async fn dedup_guard_skips_extra_dir_equal_to_home() {
        let dir = tempdir().unwrap();
        let home = dir.path().join(".neoth");
        fs::create_dir_all(&home).await.unwrap();
        fs::write(home.join("NEOTH.md"), "Global").await.unwrap();
        // Passing home as an extra_dir must NOT double-load the global NEOTH.md.
        let blocks = assemble(&home, &home, std::slice::from_ref(&home))
            .await
            .unwrap();
        assert_eq!(blocks.len(), 1, "home as extra_dir must be deduped");
        assert_eq!(blocks[0].source, BlockSource::Global);
    }

    #[tokio::test]
    async fn dedup_guard_skips_extra_dir_equal_to_cwd() {
        let dir = tempdir().unwrap();
        let home = dir.path().join(".neoth");
        let cwd = dir.path().join("proj");
        fs::create_dir_all(&home).await.unwrap();
        fs::create_dir_all(&cwd).await.unwrap();
        fs::write(cwd.join("NEOTH.md"), "Project").await.unwrap();
        // Passing cwd as an extra_dir must NOT double-load the project NEOTH.md.
        let blocks = assemble(&home, &cwd, std::slice::from_ref(&cwd))
            .await
            .unwrap();
        assert_eq!(blocks.len(), 1, "cwd as extra_dir must be deduped");
        assert_eq!(blocks[0].source, BlockSource::Project);
    }

    #[tokio::test]
    async fn missing_subdir_neoth_md_is_silently_skipped() {
        let dir = tempdir().unwrap();
        let home = dir.path().join(".neoth");
        let cwd = dir.path().join("proj");
        // sub exists as a dir but has no NEOTH.md
        let sub = dir.path().join("proj/sub");
        fs::create_dir_all(&home).await.unwrap();
        fs::create_dir_all(&cwd).await.unwrap();
        fs::create_dir_all(&sub).await.unwrap();
        let blocks = assemble(&home, &cwd, &[sub]).await.unwrap();
        assert!(blocks.is_empty(), "missing NEOTH.md in sub must not error");
    }

    #[tokio::test]
    async fn multiple_extra_dirs_all_merged() {
        let dir = tempdir().unwrap();
        let home = dir.path().join(".neoth");
        let cwd = dir.path().join("root");
        let sub_a = dir.path().join("root/a");
        let sub_b = dir.path().join("root/b");
        fs::create_dir_all(&home).await.unwrap();
        fs::create_dir_all(&cwd).await.unwrap();
        fs::create_dir_all(&sub_a).await.unwrap();
        fs::create_dir_all(&sub_b).await.unwrap();
        fs::write(home.join("NEOTH.md"), "Global").await.unwrap();
        fs::write(sub_a.join("NEOTH.md"), "Sub A rules")
            .await
            .unwrap();
        fs::write(sub_b.join("NEOTH.md"), "Sub B rules")
            .await
            .unwrap();

        let blocks = assemble(&home, &cwd, &[sub_a, sub_b]).await.unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].source, BlockSource::Global);
        assert_eq!(blocks[1].source, BlockSource::SubDir);
        assert_eq!(blocks[2].source, BlockSource::SubDir);
        let contents: Vec<&str> = blocks.iter().map(|b| b.content.as_str()).collect();
        assert!(contents.iter().any(|c| c.contains("Sub A rules")));
        assert!(contents.iter().any(|c| c.contains("Sub B rules")));
    }

    #[tokio::test]
    async fn duplicate_extra_dir_entries_are_deduped() {
        let dir = tempdir().unwrap();
        let home = dir.path().join(".neoth");
        let cwd = dir.path().join("root");
        let sub = dir.path().join("root/sub");
        fs::create_dir_all(&home).await.unwrap();
        fs::create_dir_all(&cwd).await.unwrap();
        fs::create_dir_all(&sub).await.unwrap();
        fs::write(sub.join("NEOTH.md"), "Sub rules").await.unwrap();

        // Same sub passed twice — should load only once.
        let blocks = assemble(&home, &cwd, &[sub.clone(), sub.clone()])
            .await
            .unwrap();
        assert_eq!(blocks.len(), 1, "duplicate extra_dir must be deduped");
        assert_eq!(blocks[0].source, BlockSource::SubDir);
    }
}
