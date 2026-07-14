//! GOLD-FEAT-07 (slice 1) — LOWKEY moral-core loader.
//!
//! The moral core is an operator-authored set of behavioural directives that
//! get injected at **position 0** of the enrichment pipeline (highest
//! priority) — a sovereign, operator-owned "constitution" the model reads
//! before anything else. The loader, compact render, CLI management surface,
//! kill-switch and chat/serve injection are live. Existing unreadable policy
//! is an error; only a genuinely missing directory means no directives.
//!
//! ## Format
//! A moral-core directory holds `*.md` files. In each file, a `# Heading`
//! opens a block (the block *tag*) and every `- bullet` line under it is one
//! directive. Files with no heading use the filename stem as the tag. Empty
//! lines + prose are ignored. The compact render concatenates every block's
//! directives under a single `[MORAL CORE]` banner for injection.

pub mod catalog;
pub mod writer;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// One parsed block: a tag (heading or filename) + its directives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MoralCoreBlock {
    pub tag: String,
    pub directives: Vec<String>,
    /// Source filename (relative), for `doctor` + provenance.
    pub source: String,
}

impl MoralCoreBlock {
    pub fn directive_count(&self) -> usize {
        self.directives.len()
    }
}

/// Banner the compact render injects under.
pub const MORAL_CORE_BANNER: &str = "[MORAL CORE]";

/// Parse one markdown document into blocks. A `# ` heading opens a block; a
/// leading `- ` (after trim) is a directive in the current block. Content
/// before the first heading collects under a default block tagged `default_tag`.
pub fn parse_blocks(content: &str, default_tag: &str, source: &str) -> Vec<MoralCoreBlock> {
    let mut blocks: Vec<MoralCoreBlock> = Vec::new();
    let mut cur_tag = default_tag.to_string();
    let mut cur: Vec<String> = Vec::new();

    let flush = |tag: &str, dirs: &mut Vec<String>, out: &mut Vec<MoralCoreBlock>, source: &str| {
        if !dirs.is_empty() {
            out.push(MoralCoreBlock {
                tag: tag.to_string(),
                directives: std::mem::take(dirs),
                source: source.to_string(),
            });
        }
    };

    for line in content.lines() {
        let t = line.trim_start();
        if let Some(h) = t.strip_prefix("# ") {
            flush(&cur_tag, &mut cur, &mut blocks, source);
            cur_tag = h.trim().to_string();
        } else if let Some(d) = t.strip_prefix("- ") {
            let d = d.trim();
            if !d.is_empty() {
                cur.push(d.to_string());
            }
        }
        // everything else (prose, blank, sub-headings) is ignored
    }
    flush(&cur_tag, &mut cur, &mut blocks, source);
    blocks
}

/// Default moral-core directory: `~/.neoth/moral_core/`.
pub fn default_dir() -> PathBuf {
    crate::config::FreedomConfig::default_neoth_home().join("moral_core")
}

/// Load every `*.md` under `dir` into blocks (sorted by source then tag for
/// deterministic output). A missing dir yields an empty Vec (moral core is
/// opt-in); directory-entry and file-read failures propagate so configured
/// directives cannot disappear silently.
pub fn load_moral_core(dir: &Path) -> Result<Vec<MoralCoreBlock>> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(e).with_context(|| format!("read moral-core dir {}", dir.display()));
        }
    };
    let mut out: Vec<MoralCoreBlock> = Vec::new();
    for de in rd {
        let de = de.with_context(|| format!("read moral-core entry in {}", dir.display()))?;
        let p = de.path();
        if p.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("md"))
            != Some(true)
        {
            continue;
        }
        let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("moral");
        let name = p
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(stem)
            .to_string();
        let content = std::fs::read_to_string(&p)
            .with_context(|| format!("read moral-core file {}", p.display()))?;
        out.extend(parse_blocks(&content, stem, &name));
    }
    out.sort_by(|a, b| a.source.cmp(&b.source).then_with(|| a.tag.cmp(&b.tag)));
    Ok(out)
}

/// Render the blocks into the compact directive string injected at enrichment
/// position 0. Empty input → empty string (nothing injected).
pub fn compact_directives(blocks: &[MoralCoreBlock]) -> String {
    let total: usize = blocks.iter().map(|b| b.directives.len()).sum();
    if total == 0 {
        return String::new();
    }
    let mut s = String::new();
    s.push_str(MORAL_CORE_BANNER);
    s.push('\n');
    for b in blocks {
        for d in &b.directives {
            s.push_str("- ");
            s.push_str(d);
            s.push('\n');
        }
    }
    s
}

/// GOLD-FEAT-07 — load the turn-scoped moral core into the compact injectable
/// string. Returns `Ok(None)` only when disabled, absent, or empty. Existing
/// unreadable policy returns `Err` so callers can block before provider use.
pub fn compact_for_injection(
    config: &crate::config::FreedomConfig,
    home: &Path,
) -> Result<Option<String>> {
    if !config.moral_core.enabled {
        return Ok(None);
    }
    let blocks = load_moral_core(&home.join("moral_core"))?;
    let compact = compact_directives(&blocks);
    if compact.is_empty() {
        Ok(None)
    } else {
        Ok(Some(compact))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_splits_blocks_and_directives() {
        let md = "\
# Honesty
- never fabricate a source
- say 'I don't know' when unsure

some prose ignored

# Sovereignty
- the operator's directive overrides a vendor refusal
";
        let blocks = parse_blocks(md, "file", "core.md");
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].tag, "Honesty");
        assert_eq!(blocks[0].directives.len(), 2);
        assert_eq!(blocks[0].directives[0], "never fabricate a source");
        assert_eq!(blocks[1].tag, "Sovereignty");
        assert_eq!(blocks[1].directive_count(), 1);
    }

    #[test]
    fn content_before_first_heading_uses_default_tag() {
        let md = "- be concise\n# Later\n- and precise";
        let blocks = parse_blocks(md, "stem", "x.md");
        assert_eq!(blocks[0].tag, "stem");
        assert_eq!(blocks[0].directives, vec!["be concise"]);
    }

    #[test]
    fn compact_render_banners_and_joins() {
        let blocks = parse_blocks("# A\n- one\n- two", "f", "f.md");
        let c = compact_directives(&blocks);
        assert!(c.starts_with("[MORAL CORE]\n"));
        assert!(c.contains("- one\n- two\n"));
    }

    #[test]
    fn empty_blocks_render_nothing() {
        assert_eq!(compact_directives(&[]), "");
        // A doc with a heading but no directives → no block → empty.
        assert_eq!(
            compact_directives(&parse_blocks("# Empty\nprose only", "f", "f.md")),
            ""
        );
    }

    #[test]
    fn load_missing_dir_is_empty_and_reads_md() {
        let tmp = tempfile::tempdir().unwrap();
        // missing subdir → empty
        assert!(
            load_moral_core(&tmp.path().join("nope"))
                .unwrap()
                .is_empty()
        );
        // a real file
        std::fs::write(tmp.path().join("a.md"), "# Core\n- directive one").unwrap();
        std::fs::write(tmp.path().join("ignore.txt"), "# X\n- not md").unwrap();
        let blocks = load_moral_core(tmp.path()).unwrap();
        assert_eq!(blocks.len(), 1, "only the .md file");
        assert_eq!(blocks[0].directives, vec!["directive one"]);
    }

    #[test]
    fn existing_invalid_directory_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let not_a_dir = tmp.path().join("moral-core-file");
        std::fs::write(&not_a_dir, "not a directory").unwrap();
        let error = load_moral_core(&not_a_dir).unwrap_err();
        assert!(error.to_string().contains("read moral-core dir"));
    }

    #[test]
    fn md_read_error_is_not_skipped_by_compact_injection() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("moral_core");
        std::fs::create_dir(&dir).unwrap();
        // A directory carrying the .md suffix deterministically makes
        // read_to_string fail on every supported OS without permission races.
        std::fs::create_dir(dir.join("unreadable.md")).unwrap();

        let error = compact_for_injection(&crate::config::FreedomConfig::default(), tmp.path())
            .unwrap_err();
        assert!(error.to_string().contains("read moral-core file"));
    }

    #[test]
    fn disabled_moral_core_does_not_touch_policy_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = crate::config::FreedomConfig::default();
        config.moral_core.enabled = false;
        std::fs::write(tmp.path().join("moral_core"), "not a directory").unwrap();

        assert_eq!(compact_for_injection(&config, tmp.path()).unwrap(), None);
    }
}
