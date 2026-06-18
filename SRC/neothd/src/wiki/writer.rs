//! GOLD-FEAT-03 — self-wiki build plan + write.
//!
//! Turns discovered [`WikiSource`]s into a concrete set of page writes under
//! `vault/<subdir>/`, then either executes them or (dry-run) just reports what
//! would be written. The plan/execute split keeps the page set inspectable +
//! testable without touching a real vault.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::wiki::renderer::{INDEX_SLUG, render_index, render_page};
use crate::wiki::sources::{WikiSource, discover_sources};

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
    // Reserve the index slug so a stray source can't claim + overwrite it.
    let mut seen_slugs: std::collections::HashSet<String> =
        std::collections::HashSet::from([INDEX_SLUG.to_string()]);
    for src in sources {
        // Slug collision → two sources would write the SAME page path. Skip the
        // later one (sources are pre-sorted, so this is deterministic) with a
        // warning instead of silently overwriting the first.
        if !seen_slugs.insert(src.slug.clone()) {
            tracing::warn!(
                slug = %src.slug,
                source = %src.rel_path,
                "self-wiki: duplicate slug — skipping page to avoid silent overwrite"
            );
            continue;
        }
        let siblings: Vec<&WikiSource> = sources
            .iter()
            .filter(|s| s.category == src.category)
            .collect();
        // A source that vanished or turned unreadable between discover + plan
        // must NOT abort the whole build — skip it + warn (partial wiki beats
        // no wiki).
        let body = match std::fs::read_to_string(&src.abs_path) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    source = %src.abs_path.display(),
                    error = %e,
                    "self-wiki: unreadable source — skipping page"
                );
                continue;
            }
        };
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
pub fn write_plan(
    plan: &WikiBuildPlan,
    sources_count: usize,
    dry_run: bool,
) -> Result<WikiBuildStats> {
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
pub fn build_wiki(
    source_dir: &Path,
    out_dir: &Path,
    dry_run: bool,
) -> Result<(WikiBuildStats, Vec<String>)> {
    let sources = discover_sources(source_dir)?;
    // No source docs → no wiki (a lone content-free index page is useless).
    if sources.is_empty() {
        return Ok((
            WikiBuildStats {
                sources: 0,
                pages_planned: 0,
                pages_written: 0,
                dry_run,
            },
            Vec::new(),
        ));
    }
    // Dry-run must inspect "what WOULD be written" with zero side effects AND
    // without reading any source body — so a dry-run can never fail on an
    // unreadable source. Derive the page list from the (already deduped)
    // slugs, mirroring `plan_wiki`'s collision skip so the count matches a real
    // build of all-readable sources.
    if dry_run {
        let mut seen: std::collections::HashSet<String> =
            std::collections::HashSet::from([INDEX_SLUG.to_string()]);
        let mut slugs: Vec<String> = Vec::with_capacity(sources.len() + 1);
        for s in &sources {
            if seen.insert(s.slug.clone()) {
                slugs.push(s.slug.clone());
            }
        }
        slugs.push(INDEX_SLUG.to_string());
        let stats = WikiBuildStats {
            sources: sources.len(),
            pages_planned: slugs.len(),
            pages_written: 0,
            dry_run: true,
        };
        return Ok((stats, slugs));
    }
    let plan = plan_wiki(&sources, out_dir)?;
    let slugs: Vec<String> = plan.pages.iter().map(|p| p.slug.clone()).collect();
    let stats = write_plan(&plan, sources.len(), false)?;
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
    fn duplicate_slugs_do_not_overwrite() {
        // `a.b.md` and `a-b.md` both sanitize to slug "a-b" → without the dedup
        // guard the second page would silently overwrite the first.
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        std::fs::write(d.join("a.b.md"), "# AB one\n").unwrap();
        std::fs::write(d.join("a-b.md"), "# AB two\n").unwrap();
        let sources = discover_sources(d).unwrap();
        assert_eq!(sources.len(), 2, "both files discovered");
        let plan = plan_wiki(&sources, Path::new("/out")).unwrap();
        let ab_pages = plan.pages.iter().filter(|p| p.slug == "a-b").count();
        assert_eq!(ab_pages, 1, "collision skipped, not duplicated");
        assert_eq!(plan.pages.len(), 2, "1 unique source page + index");
    }

    #[test]
    fn unreadable_source_is_skipped_not_fatal() {
        // A source listed in `sources` but missing on disk (vanished between
        // discover + plan) must be skipped, not abort the whole build.
        let tmp = tempfile::tempdir().unwrap();
        let good = tmp.path().join("SPEC_ok.md");
        std::fs::write(&good, "# Ok\n\nbody").unwrap();
        let sources = vec![
            WikiSource {
                title: "Ok".into(),
                slug: "SPEC_ok".into(),
                rel_path: "SPEC_ok.md".into(),
                abs_path: good,
                category: crate::wiki::SourceCategory::Spec,
            },
            WikiSource {
                title: "Gone".into(),
                slug: "SPEC_gone".into(),
                rel_path: "SPEC_gone.md".into(),
                abs_path: tmp.path().join("SPEC_gone.md"), // never created
                category: crate::wiki::SourceCategory::Spec,
            },
        ];
        let plan = plan_wiki(&sources, Path::new("/out")).unwrap();
        // The good page + index survive; the missing one was skipped.
        assert!(plan.pages.iter().any(|p| p.slug == "SPEC_ok"));
        assert!(!plan.pages.iter().any(|p| p.slug == "SPEC_gone"));
        assert_eq!(plan.pages.len(), 2);
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
    fn empty_source_dir_yields_no_pages() {
        let empty = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let (stats, slugs) = build_wiki(empty.path(), &out.path().join("W"), true).unwrap();
        assert_eq!(stats.sources, 0);
        assert_eq!(stats.pages_planned, 0, "no content-free index page");
        assert!(slugs.is_empty());
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
