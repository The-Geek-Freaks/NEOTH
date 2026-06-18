//! GOLD-FEAT-07 — moral-core write operations.
//!
//! Every mutation of `~/.neoth/moral_core/*.md` goes through this module so the
//! invariants live in one place: a path-traversal-safe category name, an atomic
//! write (tmp + rename, never a half-written file), and owner-only file
//! permissions. The `neoth moral-core {init,new,add,remove,enable,disable,template}`
//! CLI is a thin shell over these functions; the GUI editor calls them
//! in-process.
//!
//! The loader in [`super`] keys off the `.md` extension, so `disable_block`
//! simply renames to `<stem>.md.disabled` — invisible to the injection
//! pipeline without any loader change.

use std::path::Path;

use anyhow::{Context, Result, bail};

use super::catalog;

/// Maximum category-name length (a filesystem-friendly bound).
const MAX_CATEGORY_LEN: usize = 64;

/// Validate a category (file-stem) name: `[a-z0-9_-]{1,64}`. This is the
/// path-traversal guard — the allowed set excludes `.` and `/` so neither
/// `..` nor an absolute/relative escape can be constructed.
pub fn validate_category(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_CATEGORY_LEN {
        bail!(
            "category name must be 1..={MAX_CATEGORY_LEN} chars, got {} ",
            name.len()
        );
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    {
        bail!("category name must match [a-z0-9_-]+, got {name:?}");
    }
    Ok(())
}

/// Validate one directive line: non-empty after trim, single line (no newline).
fn validate_directive(directive: &str) -> Result<String> {
    let d = directive.trim();
    if d.is_empty() {
        bail!("directive must not be empty");
    }
    if d.contains('\n') || d.contains('\r') {
        bail!("a directive is a single line — it must not contain a line break");
    }
    Ok(d.to_string())
}

/// Title-case a stem for a default `# Heading` (`anti_hedging` -> `Anti_hedging`).
fn heading_from_stem(stem: &str) -> String {
    let mut chars = stem.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Write `content` atomically to `dir/<stem>.md` (tmp + rename) and restrict it
/// to the owner. The rename is atomic on the same volume, so a reader never
/// sees a partial file.
pub fn atomic_write_block(dir: &Path, stem: &str, content: &str) -> Result<()> {
    validate_category(stem)?;
    std::fs::create_dir_all(dir)
        .with_context(|| format!("create moral-core dir {}", dir.display()))?;
    let target = dir.join(format!("{stem}.md"));
    let tmp = dir.join(format!(".{stem}.md.tmp"));
    std::fs::write(&tmp, content).with_context(|| format!("write tmp {}", tmp.display()))?;
    restrict_to_owner(&tmp);
    std::fs::rename(&tmp, &target)
        .with_context(|| format!("atomic rename -> {}", target.display()))?;
    Ok(())
}

/// Append one `- <directive>` bullet to `dir/<stem>.md`, creating the file with
/// a `# <Heading>` if it does not exist yet.
pub fn append_directive(dir: &Path, stem: &str, directive: &str) -> Result<()> {
    validate_category(stem)?;
    let directive = validate_directive(directive)?;
    let target = dir.join(format!("{stem}.md"));
    let mut existing = if target.exists() {
        std::fs::read_to_string(&target).with_context(|| format!("read {}", target.display()))?
    } else {
        format!("# {}\n", heading_from_stem(stem))
    };
    if !existing.ends_with('\n') {
        existing.push('\n');
    }
    existing.push_str("- ");
    existing.push_str(&directive);
    existing.push('\n');
    atomic_write_block(dir, stem, &existing)
}

/// Remove the `index`-th directive bullet (1-based) from `dir/<stem>.md`,
/// preserving the heading + any prose.
pub fn remove_directive(dir: &Path, stem: &str, index: usize) -> Result<()> {
    validate_category(stem)?;
    if index == 0 {
        bail!("directive index is 1-based; got 0");
    }
    let target = dir.join(format!("{stem}.md"));
    let content =
        std::fs::read_to_string(&target).with_context(|| format!("read {}", target.display()))?;
    let mut bullet = 0usize;
    let mut kept: Vec<&str> = Vec::new();
    for line in content.lines() {
        if line.trim_start().starts_with("- ") {
            bullet += 1;
            if bullet == index {
                continue; // drop this one
            }
        }
        kept.push(line);
    }
    if index > bullet {
        bail!("index {index} out of range (block has {bullet} directive(s))");
    }
    let mut out = kept.join("\n");
    out.push('\n');
    atomic_write_block(dir, stem, &out)
}

/// Disable a block: `<stem>.md` -> `<stem>.md.disabled` (loader skips non-`.md`).
pub fn disable_block(dir: &Path, stem: &str) -> Result<()> {
    validate_category(stem)?;
    let src = dir.join(format!("{stem}.md"));
    let dst = dir.join(format!("{stem}.md.disabled"));
    if !src.exists() {
        bail!("no enabled block {stem} to disable");
    }
    std::fs::rename(&src, &dst).with_context(|| format!("disable block {stem}"))
}

/// Re-enable a block: `<stem>.md.disabled` -> `<stem>.md`.
pub fn enable_block(dir: &Path, stem: &str) -> Result<()> {
    validate_category(stem)?;
    let src = dir.join(format!("{stem}.md.disabled"));
    let dst = dir.join(format!("{stem}.md"));
    if !src.exists() {
        bail!("no disabled block {stem} to enable");
    }
    std::fs::rename(&src, &dst).with_context(|| format!("enable block {stem}"))
}

/// Apply a built-in catalog template: append each of its directives to the
/// target category file (the template's `default_category` unless `into` is
/// given). Returns the number of directives appended.
pub fn apply_template(dir: &Path, template_id: &str, into: Option<&str>) -> Result<usize> {
    let entry = catalog::find(template_id)
        .with_context(|| format!("template {template_id:?} is not in the built-in catalog"))?;
    let stem = into.unwrap_or(entry.default_category);
    validate_category(stem)?;
    for d in entry.directives {
        append_directive(dir, stem, d)?;
    }
    Ok(entry.directives.len())
}

/// Scaffold a starter moral core: a few sensible defaults so a new operator
/// sees the shape immediately. Idempotent unless `force` (which overwrites the
/// three scaffolded files). Returns the template ids applied.
pub fn init_starter(dir: &Path, force: bool) -> Result<Vec<&'static str>> {
    const STARTER: &[&str] = &[
        "honesty/no-fabrication",
        "voice/match-register",
        "anti_hedging/no-apologies",
    ];
    for t in STARTER {
        if let Some(entry) = catalog::find(t) {
            let target = dir.join(format!("{}.md", entry.default_category));
            if target.exists() && !force {
                continue;
            }
            if force {
                // start the file fresh on --force
                let _ = std::fs::remove_file(&target);
            }
            apply_template(dir, t, None)?;
        }
    }
    Ok(STARTER.to_vec())
}

/// Restrict a path to the owner. Unix: chmod 0600. Windows: owner-only DACL via
/// the shared `wal::win_acl` helper. Best-effort — a failure logs but does not
/// abort the write (the operator's umask/profile ACL may already cover it).
fn restrict_to_owner(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            tracing::warn!(error = %e, path = %path.display(), "moral-core: chmod 0600 failed");
        }
    }
    #[cfg(windows)]
    {
        if let Err(e) = crate::wal::win_acl::restrict_to_owner(path) {
            tracing::warn!(error = %e, path = %path.display(), "moral-core: DACL restrict failed");
        }
    }
    #[cfg(not(any(unix, windows)))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::moral_core::load_moral_core;

    #[test]
    fn validate_category_accepts_safe_rejects_traversal() {
        assert!(validate_category("honesty").is_ok());
        assert!(validate_category("anti_hedging").is_ok());
        assert!(validate_category("voice-2").is_ok());
        assert!(validate_category("").is_err());
        assert!(validate_category("../etc").is_err());
        assert!(validate_category("a/b").is_err());
        assert!(validate_category("UPPER").is_err());
        assert!(validate_category(&"x".repeat(65)).is_err());
    }

    #[test]
    fn append_creates_file_with_heading_then_appends() {
        let tmp = tempfile::tempdir().unwrap();
        append_directive(tmp.path(), "honesty", "never fabricate a source").unwrap();
        append_directive(tmp.path(), "honesty", "say 'I don't know' when unsure").unwrap();
        let blocks = load_moral_core(tmp.path()).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].tag, "Honesty");
        assert_eq!(blocks[0].directives.len(), 2);
    }

    #[test]
    fn append_rejects_empty_and_multiline_directives() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(append_directive(tmp.path(), "x", "   ").is_err());
        assert!(append_directive(tmp.path(), "x", "line one\nline two").is_err());
    }

    #[test]
    fn remove_directive_drops_the_indexed_bullet() {
        let tmp = tempfile::tempdir().unwrap();
        append_directive(tmp.path(), "voice", "be blunt").unwrap();
        append_directive(tmp.path(), "voice", "be concise").unwrap();
        append_directive(tmp.path(), "voice", "no filler").unwrap();
        remove_directive(tmp.path(), "voice", 2).unwrap(); // drop "be concise"
        let blocks = load_moral_core(tmp.path()).unwrap();
        assert_eq!(blocks[0].directives, vec!["be blunt", "no filler"]);
        assert!(
            remove_directive(tmp.path(), "voice", 9).is_err(),
            "out of range"
        );
    }

    #[test]
    fn disable_then_enable_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        append_directive(tmp.path(), "latitude", "full depth").unwrap();
        disable_block(tmp.path(), "latitude").unwrap();
        // disabled file is invisible to the loader
        assert!(load_moral_core(tmp.path()).unwrap().is_empty());
        enable_block(tmp.path(), "latitude").unwrap();
        assert_eq!(load_moral_core(tmp.path()).unwrap().len(), 1);
    }

    #[test]
    fn apply_template_appends_catalog_directives() {
        let tmp = tempfile::tempdir().unwrap();
        let n = apply_template(tmp.path(), "honesty/no-fabrication", None).unwrap();
        assert!(n >= 1);
        let blocks = load_moral_core(tmp.path()).unwrap();
        assert_eq!(blocks[0].tag, "Honesty");
        assert_eq!(blocks[0].directives.len(), n);
        // unknown template id errors
        assert!(apply_template(tmp.path(), "nope/none", None).is_err());
    }

    #[test]
    fn init_starter_is_idempotent_without_force() {
        let tmp = tempfile::tempdir().unwrap();
        let first = init_starter(tmp.path(), false).unwrap();
        assert_eq!(first.len(), 3);
        let before = load_moral_core(tmp.path()).unwrap();
        let total_before: usize = before.iter().map(|b| b.directives.len()).sum();
        // second run without force must NOT duplicate directives
        init_starter(tmp.path(), false).unwrap();
        let after = load_moral_core(tmp.path()).unwrap();
        let total_after: usize = after.iter().map(|b| b.directives.len()).sum();
        assert_eq!(total_before, total_after, "idempotent without --force");
    }
}
