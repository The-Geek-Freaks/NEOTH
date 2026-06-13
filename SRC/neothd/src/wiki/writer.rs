//! GOLD-FEAT-03 — self-wiki build plan + write.
//!
//! Turns discovered [`WikiSource`]s into a concrete set of page writes under
//! `vault/<subdir>/`, then either executes them or (dry-run) just reports what
//! would be written. The plan/execute split keeps the page set inspectable +
//! testable without touching a real vault.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::wiki::renderer::{render_index, render_page, INDEX_SLUG};
use crate::wiki::sources::{discover_sources, WikiSource};

/// One planned page write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedPage {
    pub path: PathBuf,
    pub slug: String,
    pub content: String,
}

/// The full set of pages a build would write into `out_dir`.
#[derive(Clone, Debug)]
pub struct WikiBuildPlan {
    pub out_dir: PathBuf,
    pub pages: Vec<PlannedPage>,
}

/// Outcome counters for the CLI summary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WikiBuildStats {
    /// Source docs discovered.
    pub sources: usize,
    /// Pages the plan contains (one per source + the index).
    pub pages_planned: usize,
    /// Pages actually written (0 on dry-run).
    pub pages_written: usize,
    pub dry_run: bool,
}

/// Build the page set for `out_dir`: one page per source (cross-linked to its
/// same-category siblings) plus the index. Reads each source body once.
pub fn plan_wiki(sources: &[WikiSource], out_dir: &Path) -> Result<WikiBuildPlan> {
    let mut pages = Vec::with_capacity(sources.len() + 1);
    for src in sources {
        let siblings: Vec<&WikiSource> = sources
            .iter()
            .filter(|s| s.category == src.category)
            .collect();
        let body = std::fs::read_to_string(&src.abs_path)
            .with_context(|| format!("read self-wiki source {}", src.abs_path.display()))?;
        let content = render_page(src, &siblings, &body);
        pages.push(PlannedPage {
            path: out_dir.join(format!("{}.md", src.slug)),
            slug: src.slug.clone(),
            content,
        });
    }
    pages.push(PlannedPage {
        path: out_dir.join(format!("{INDEX_SLUG}.md")),
        slug: INDEX_SLUG.to_string(),
        content: render_index(sources),
    });
    Ok(WikiBuildPlan {
        out_dir: out_dir.to_path_buf(),
        pages,
    })
}

/// Execute (or, on `dry_run`, simulate) the plan. Real writes create `out_dir`
/// then write each page; dry-run touches nothing and only fills the counters.
pub fn write_plan(plan: &WikiBuildPlan, sources_count: usize, dry_run: bool) -> Result<WikiBuildStats> {
    let mut stats = WikiBuildStats {
        sources: sources_count,
        pages_planned: plan.pages.len(),
        pages_written: 0,
        dry_run,
    };
    if dry_run {
        return Ok(stats);
    }
    std::fs::create_dir_all(&plan.out_dir)
        .with_context(|| format!("create self-wiki out dir {}", plan.out_dir.display()))?;
    for p in &plan.pages {
        std::fs::write(&p.path, &p.content)
            .with_context(|| format!("write self-wiki page {}", p.path.display()))?;
        stats.pages_written += 1;
    }
    Ok(stats)
}

/// Discover → plan → write. The CLI entry point. Returns the stats + the
/// ordered page slugs (for the dry-run listing).
pub fn build_wiki(source_dir: &Path, out_dir: &Path, dry_run: bool) -> Result<(WikiBuildStats, Vec<String>)> {
    let sources = discover_sources(source_dir)?;
    let plan = plan_wiki(&sources, out_dir)?;
    let slugs: Vec<String> = plan.pages.iter().map(|p| p.slug.clone()).collect();
    let stats = write_plan(&plan, sources.len(), dry_run)?;
    Ok((stats, slugs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_dir() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        std::fs::write(d.join("SPEC_a.md"), "# Spec A\n\nalpha body").unwrap();
        std::fs::write(d.join("SPEC_b.md"), "# Spec B\n\nbeta body").unwrap();
        std::fs::write(d.join("00_DESIGN.md"), "# Design\n\ndesign body").unwrap();
        tmp
    }

    #[test]
    fn plan_has_one_page_per_source_plus_index() {
        let tmp = fixture_dir();
        let sources = discover_sources(tmp.path()).unwrap();
        let plan = plan_wiki(&sources, Path::new("/out")).unwrap();
        assert_eq!(sources.len(), 3);
        assert_eq!(plan.pages.len(), 4, "3 sources + 1 index");
        assert!(plan.pages.iter().any(|p| p.slug == INDEX_SLUG));
        // SPEC_a's page cross-links SPEC_b (same category) but not the design doc.
        let a = plan.pages.iter().find(|p| p.slug == "SPEC_a").unwrap();
        assert!(a.content.contains("[[SPEC_b]]"));
        assert!(!a.content.contains("[[00_DESIGN]]"));
    }

    #[test]
    fn dry_run_writes_nothing() {
        let tmp = fixture_dir();
        let out = tempfile::tempdir().unwrap();
        let out_sub = out.path().join("NEOTH-Wiki");
        let (stats, slugs) = build_wiki(tmp.path(), &out_sub, true).unwrap();
        assert!(stats.dry_run);
        assert_eq!(stats.sources, 3);
        assert_eq!(stats.pages_planned, 4);
        assert_eq!(stats.pages_written, 0);
        assert!(!out_sub.exists(), "dry-run must not create the out dir");
        assert!(slugs.contains(&INDEX_SLUG.to_string()));
    }

    #[test]
    fn real_build_writes_every_page() {
        let tmp = fixture_dir();
        let out = tempfile::tempdir().unwrap();
        let out_sub = out.path().join("NEOTH-Wiki");
        let (stats, _) = build_wiki(tmp.path(), &out_sub, false).unwrap();
        assert_eq!(stats.pages_written, 4);
        assert!(out_sub.join("SPEC_a.md").exists());
        assert!(out_sub.join("NEOTH-Wiki-Index.md").exists());
        let idx = std::fs::read_to_string(out_sub.join("NEOTH-Wiki-Index.md")).unwrap();
        assert!(idx.contains("# NEOTH Self-Wiki"));
        assert!(idx.contains("[[SPEC_a]]"));
    }
}
