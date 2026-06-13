//! GOLD-FEAT-03 — self-wiki source discovery.
//!
//! Enumerates NEOTH's own design corpus (the `PLAN/` markdown docs — SPECs,
//! design blueprints, Chorus verdicts) and turns each file into a
//! [`WikiSource`] the renderer can lay out as an interlinked Obsidian page.
//! Pure of I/O beyond a single directory read + per-file title sniff, so it is
//! exercised against a `tempfile` fixture rather than the live repo.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Coarse classification driven by the filename prefix. Drives page tags +
/// which siblings a page cross-links to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceCategory {
    /// `SPEC_*.md` — a component specification.
    Spec,
    /// `00_DESIGN*` / `BLUEPRINT*` — top-level design docs.
    Design,
    /// `CHORUS_*` — multi-model review verdicts.
    Chorus,
    /// Everything else under `PLAN/`.
    Other,
}

impl SourceCategory {
    /// Classify by filename (case-insensitive prefix match).
    pub fn classify(file_name: &str) -> Self {
        let up = file_name.to_ascii_uppercase();
        if up.starts_with("SPEC_") || up.starts_with("SPEC-") {
            SourceCategory::Spec
        } else if up.starts_with("00_DESIGN") || up.starts_with("BLUEPRINT") {
            SourceCategory::Design
        } else if up.starts_with("CHORUS_") {
            SourceCategory::Chorus
        } else {
            SourceCategory::Other
        }
    }

    /// Stable lower-kebab tag used in page frontmatter + the index grouping.
    pub fn tag(self) -> &'static str {
        match self {
            SourceCategory::Spec => "spec",
            SourceCategory::Design => "design",
            SourceCategory::Chorus => "chorus",
            SourceCategory::Other => "other",
        }
    }

    /// Human heading for the index page section.
    pub fn heading(self) -> &'static str {
        match self {
            SourceCategory::Spec => "Specifications",
            SourceCategory::Design => "Design",
            SourceCategory::Chorus => "Chorus Verdicts",
            SourceCategory::Other => "Other",
        }
    }
}

/// One design doc resolved to its wiki identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WikiSource {
    /// Display title (the doc's first `# ` heading, else the prettified stem).
    pub title: String,
    /// The Obsidian page basename (no extension) — the `[[wikilink]]` target.
    pub slug: String,
    /// Path relative to the scanned source dir (recorded in frontmatter).
    pub rel_path: String,
    /// Absolute path on disk (read by the renderer for the body excerpt).
    pub abs_path: PathBuf,
    pub category: SourceCategory,
}

/// Prettify a filename stem into a fallback title: drop the extension, split on
/// `_`/`-`, title-case words, but keep an embedded date/version token as-is.
pub fn prettify_stem(stem: &str) -> String {
    stem.split(['_', '-'])
        .filter(|w| !w.is_empty())
        .map(|w| {
            // Keep tokens that look like versions/dates/all-caps acronyms.
            let is_tokenish = w.chars().any(|c| c.is_ascii_digit())
                || (w.len() <= 4 && w.chars().all(|c| c.is_ascii_uppercase()));
            if is_tokenish {
                w.to_string()
            } else {
                let mut cs = w.chars();
                match cs.next() {
                    Some(f) => f.to_ascii_uppercase().to_string() + &cs.as_str().to_ascii_lowercase(),
                    None => String::new(),
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The page basename: the file stem, with any character outside
/// `[A-Za-z0-9 _-]` replaced by `-` so it is a safe Obsidian note name + a
/// valid filename on every OS. Never empty.
pub fn slug_for(stem: &str) -> String {
    let s: String = stem
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == ' ' || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = s.trim_matches(['-', ' ']).to_string();
    if trimmed.is_empty() {
        "untitled".to_string()
    } else {
        trimmed
    }
}

/// Read the first markdown `# ` heading from a doc, if any (the authoritative
/// title). Scans only the first ~40 lines so a huge doc isn't slurped.
fn first_heading(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    content.lines().take(40).find_map(|l| {
        let t = l.trim_start();
        t.strip_prefix("# ").map(|h| h.trim().to_string())
    })
}

/// Discover every `*.md` directly under `source_dir` and resolve each to a
/// [`WikiSource`], sorted by (category, slug) for deterministic output.
/// Non-markdown files + subdirectories are ignored. A missing dir is an error.
pub fn discover_sources(source_dir: &Path) -> Result<Vec<WikiSource>> {
    let rd = std::fs::read_dir(source_dir)
        .with_context(|| format!("read self-wiki source dir {}", source_dir.display()))?;
    let mut out: Vec<WikiSource> = Vec::new();
    for de in rd.flatten() {
        let abs_path = de.path();
        if !abs_path.is_file() {
            continue;
        }
        if abs_path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let file_name = match abs_path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let stem = abs_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("untitled");
        let category = SourceCategory::classify(&file_name);
        let title = first_heading(&abs_path).unwrap_or_else(|| prettify_stem(stem));
        out.push(WikiSource {
            title,
            slug: slug_for(stem),
            rel_path: file_name,
            abs_path,
            category,
        });
    }
    out.sort_by(|a, b| {
        a.category
            .tag()
            .cmp(b.category.tag())
            .then_with(|| a.slug.cmp(&b.slug))
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).unwrap();
    }

    #[test]
    fn classify_by_prefix() {
        assert_eq!(SourceCategory::classify("SPEC_channels.md"), SourceCategory::Spec);
        assert_eq!(SourceCategory::classify("00_DESIGN_v1.1.md"), SourceCategory::Design);
        assert_eq!(SourceCategory::classify("BLUEPRINT_v06.md"), SourceCategory::Design);
        assert_eq!(SourceCategory::classify("CHORUS_pick6.md"), SourceCategory::Chorus);
        assert_eq!(SourceCategory::classify("NOTES.md"), SourceCategory::Other);
    }

    #[test]
    fn prettify_keeps_version_and_acronym_tokens() {
        // Short all-caps tokens (≤4) stay as acronyms; longer words title-case;
        // tokens carrying a digit (versions/dates) are preserved verbatim.
        assert_eq!(prettify_stem("SPEC_channels"), "SPEC Channels");
        assert_eq!(prettify_stem("local_inference"), "Local Inference");
        assert_eq!(prettify_stem("00_DESIGN_v1.1_FINAL"), "00 Design v1.1 Final");
    }

    #[test]
    fn slug_sanitizes_unsafe_chars_and_never_empty() {
        assert_eq!(slug_for("SPEC_channels"), "SPEC_channels");
        assert_eq!(slug_for("a/b:c"), "a-b-c");
        assert_eq!(slug_for("***"), "untitled");
    }

    #[test]
    fn discover_finds_md_titles_categories_sorted() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        write(d, "SPEC_channels.md", "# Channel API Spec\n\nbody");
        write(d, "CHORUS_x.md", "no heading here\njust text");
        write(d, "README.txt", "ignored (not md)");
        std::fs::create_dir(d.join("subdir")).unwrap(); // ignored

        let sources = discover_sources(d).unwrap();
        assert_eq!(sources.len(), 2, "only the two .md files");
        // Sorted: chorus < spec by tag.
        assert_eq!(sources[0].category, SourceCategory::Chorus);
        assert_eq!(
            sources[0].title, "Chorus X",
            "no '# ' heading → prettified full stem"
        );
        assert_eq!(sources[1].category, SourceCategory::Spec);
        assert_eq!(sources[1].title, "Channel API Spec", "'# ' heading wins");
        assert_eq!(sources[1].slug, "SPEC_channels");
    }

    #[test]
    fn discover_missing_dir_errors() {
        assert!(discover_sources(Path::new("/no/such/neoth/wiki/dir")).is_err());
    }
}
