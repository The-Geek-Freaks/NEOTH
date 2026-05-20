//! ADR persistence — Phase 31 R-21 ADR-2 + ADR-3.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::extractor::Decision;
use crate::config::FreedomConfig;

/// `~/.neoth/adr/`.
pub fn default_adr_dir() -> PathBuf {
    FreedomConfig::default_neoth_home().join("adr")
}

/// One entry in the ADR log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdrFile {
    pub number: u32,
    pub title: String,
    pub path: PathBuf,
}

/// Highest existing ADR number + 1. Returns 1 when the dir is empty or
/// missing. Never reuses a number, even if files were deleted out from
/// under us — operator-visible numbering must stay monotonic.
pub fn next_number(dir: &Path) -> u32 {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 1;
    };
    let max = rd
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let stem = name.strip_suffix(".md")?;
            let (num, _) = stem.split_once('-')?;
            num.parse::<u32>().ok()
        })
        .max()
        .unwrap_or(0);
    max + 1
}

/// Write a new ADR. Builds the filename `NNNN-<slug>.md`, the Nygard-style
/// body, and returns the file path. Parent dir created on demand.
pub fn write_adr(dir: &Path, d: &Decision) -> Result<PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("create adr dir {}", dir.display()))?;
    let n = next_number(dir);
    let slug = slugify(&d.title);
    let path = dir.join(format!("{:04}-{}.md", n, slug));
    let body = render_adr_md(n, &d.title, &d.body);
    std::fs::write(&path, body).with_context(|| format!("write adr {}", path.display()))?;
    Ok(path)
}

/// List all ADR files (ordered by number ascending).
pub fn list_adrs(dir: &Path) -> Result<Vec<AdrFile>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in
        std::fs::read_dir(dir).with_context(|| format!("read adr dir {}", dir.display()))?
    {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(".md") else {
            continue;
        };
        let Some((num_str, rest)) = stem.split_once('-') else {
            continue;
        };
        let Ok(number) = num_str.parse::<u32>() else {
            continue;
        };
        out.push(AdrFile {
            number,
            title: rest.replace('-', " "),
            path: entry.path(),
        });
    }
    out.sort_by_key(|a| a.number);
    Ok(out)
}

fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_dash = false;
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash && !out.is_empty() {
            out.push('-');
            last_dash = true;
        }
    }
    let trimmed: String = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "decision".to_string()
    } else {
        trimmed.chars().take(60).collect()
    }
}

fn render_adr_md(number: u32, title: &str, body: &str) -> String {
    let now_iso = chrono::Utc::now().format("%Y-%m-%d").to_string();
    format!(
        "# ADR-{:04}: {title}\n\n\
         **Status:** Proposed  \n\
         **Date:** {now_iso}\n\n\
         ## Context\n\n\
         (Captured from a NEOTH provider response by `adr::extract_decisions`. \
         Edit this section to flesh out the surrounding context.)\n\n\
         ## Decision\n\n\
         {body}\n\n\
         ## Consequences\n\n\
         (To be filled in by the operator.)\n",
        number,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn next_number_starts_at_one_on_empty_dir() {
        let dir = tempdir().unwrap();
        assert_eq!(next_number(dir.path()), 1);
    }

    #[test]
    fn next_number_picks_max_plus_one() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("0001-first.md"), "x").unwrap();
        std::fs::write(dir.path().join("0042-skipped.md"), "x").unwrap();
        std::fs::write(dir.path().join("0007-mid.md"), "x").unwrap();
        assert_eq!(next_number(dir.path()), 43);
    }

    #[test]
    fn next_number_ignores_non_adr_files() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("random.txt"), "x").unwrap();
        std::fs::write(dir.path().join("0003-real.md"), "x").unwrap();
        assert_eq!(next_number(dir.path()), 4);
    }

    #[test]
    fn write_adr_creates_numbered_file() {
        let dir = tempdir().unwrap();
        let d = Decision {
            title: "Use rusqlite bundled mode".into(),
            body: "Use rusqlite bundled mode for self-contained build.".into(),
        };
        let path = write_adr(dir.path(), &d).unwrap();
        let name = path.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("0001-"));
        assert!(name.contains("rusqlite"));
        assert!(name.ends_with(".md"));
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("# ADR-0001"));
        assert!(body.contains("Use rusqlite bundled mode"));
        assert!(body.contains("**Status:** Proposed"));
    }

    #[test]
    fn write_adr_numbers_monotonically_across_calls() {
        let dir = tempdir().unwrap();
        let d1 = Decision {
            title: "alpha".into(),
            body: "a".into(),
        };
        let d2 = Decision {
            title: "beta".into(),
            body: "b".into(),
        };
        let p1 = write_adr(dir.path(), &d1).unwrap();
        let p2 = write_adr(dir.path(), &d2).unwrap();
        assert!(p1.to_string_lossy().contains("0001"));
        assert!(p2.to_string_lossy().contains("0002"));
    }

    #[test]
    fn list_adrs_returns_sorted() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("0005-five.md"), "x").unwrap();
        std::fs::write(dir.path().join("0001-one.md"), "x").unwrap();
        std::fs::write(dir.path().join("0003-three.md"), "x").unwrap();
        let list = list_adrs(dir.path()).unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].number, 1);
        assert_eq!(list[1].number, 3);
        assert_eq!(list[2].number, 5);
    }

    #[test]
    fn slugify_handles_unicode_and_punctuation() {
        assert_eq!(
            slugify("Use Rusqlite Bundled Mode!"),
            "use-rusqlite-bundled-mode"
        );
        assert_eq!(
            slugify("WAL-Rotation @ 16 MiB / 24h"),
            "wal-rotation-16-mib-24h"
        );
        assert_eq!(slugify("   "), "decision");
    }
}
