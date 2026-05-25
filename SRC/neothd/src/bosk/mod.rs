//! Q-02 (Session 24) — Book of Secret Knowledge (BOSK) → TOML
//! skill-catalog parser.
//!
//! Operators frequently know "there's a CLI tool that does X" but
//! can't remember the name. The Book of Secret Knowledge
//! (github.com/trimstray/the-book-of-secret-knowledge) is the canonical
//! community catalog of those tools; this module parses a TOML
//! distillation of it into a typed [`SkillCatalog`] NEOTH can index
//! against operator prompts so `neoth chat "what's that thing for
//! finding files faster than find"` can surface `fd` from the
//! catalog without round-tripping to a cloud LLM.
//!
//! ## On-disk shape (TOML)
//!
//! ```toml
//! # ~/.neoth/bosk/catalog.toml
//!
//! [[entry]]
//! name = "ripgrep"
//! category = "cli/search"
//! description = "Fast recursive grep replacement"
//! url = "https://github.com/BurntSushi/ripgrep"
//! install = "cargo install ripgrep"
//! tags = ["cli", "search", "performance"]
//!
//! [[entry]]
//! name = "fd"
//! category = "cli/files"
//! description = "Simple, fast user-friendly alternative to find"
//! url = "https://github.com/sharkdp/fd"
//! tags = ["cli", "filesystem"]
//! ```
//!
//! Each `[[entry]]` becomes one [`SkillEntry`]; the catalog is the
//! ordered list. Recall queries match against `name + description +
//! tags + category` so a fuzzy "fast find" lands `fd` even when the
//! operator didn't know the exact name.
//!
//! ## Scope of this commit (Q-02)
//!
//! - Define the TOML schema as a typed `SkillCatalog`.
//! - Parse + validate. Reject duplicate names, empty fields, malformed URLs.
//! - Tests covering happy path + every reject case.
//!
//! Indexing the catalog into the recall surface + wiring a `neoth
//! bosk lookup <query>` CLI subcommand are follow-ups. The parser
//! primitive is what's blocking — without a typed catalog every
//! downstream consumer would re-implement the TOML shape.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// One ordered list of [`SkillEntry`]s, parsed from a single TOML
/// document. The order matches the source file so the operator's
/// hand-curated priority survives serialisation round-trips.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillCatalog {
    /// Optional catalog-level metadata: title, source URL, version.
    /// Operators forking the upstream BOSK retain attribution here.
    #[serde(default)]
    pub meta: Option<CatalogMeta>,
    /// The catalog entries. Empty is valid (operator just stamped
    /// the meta and hasn't added anything yet) but parse rejects
    /// any entry with empty `name` / `description`.
    #[serde(default, rename = "entry")]
    pub entries: Vec<SkillEntry>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogMeta {
    pub title: Option<String>,
    pub source_url: Option<String>,
    pub version: Option<String>,
    pub upstream_revision: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillEntry {
    /// Stable identifier — must be non-empty + unique within the
    /// catalog. `neoth bosk lookup <name>` matches against this
    /// exactly before falling back to fuzzy match.
    pub name: String,
    /// Slash-delimited category path like `cli/search` or
    /// `dev/build`. Lets the operator narrow `neoth bosk list
    /// --category cli` to one slice.
    pub category: String,
    /// One-line description. Required + non-empty. Surfaced in
    /// lookup results + the chat-side suggestion text.
    pub description: String,
    /// Optional upstream URL (homepage / repo / docs).
    #[serde(default)]
    pub url: Option<String>,
    /// Optional install command line (`brew install fd` /
    /// `cargo install ripgrep` / `apt install rsync`).
    #[serde(default)]
    pub install: Option<String>,
    /// Free-form tags for fuzzy recall scoring. Lowercased on parse.
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CatalogError {
    #[error("entry #{idx} has empty `name`")]
    EmptyName { idx: usize },
    #[error("entry #{idx} has empty `description`")]
    EmptyDescription { idx: usize },
    #[error("entry #{idx} has empty `category`")]
    EmptyCategory { idx: usize },
    #[error("duplicate entry name `{name}` (already used at entry #{first_idx})")]
    DuplicateName { name: String, first_idx: usize },
    #[error("entry #{idx} url must start with http:// or https:// (got: {got:?})")]
    InvalidUrlScheme { idx: usize, got: String },
    #[error("TOML parse error: {0}")]
    Parse(String),
}

/// Parse + validate a BOSK catalog from TOML bytes. Performs the
/// same per-entry checks as [`validate_catalog`] but additionally
/// normalises tags to lowercase so recall scoring is case-insensitive.
pub fn parse_catalog(toml_bytes: &[u8]) -> Result<SkillCatalog, CatalogError> {
    let raw = std::str::from_utf8(toml_bytes)
        .map_err(|e| CatalogError::Parse(format!("non-utf8 catalog.toml: {e}")))?;
    let mut catalog: SkillCatalog =
        toml::from_str(raw).map_err(|e| CatalogError::Parse(e.to_string()))?;
    // Normalise tags BEFORE validation so duplicate-tag detection
    // (a future tightening) sees the canonical form.
    for entry in &mut catalog.entries {
        for tag in &mut entry.tags {
            *tag = tag.to_lowercase();
        }
    }
    validate_catalog(&catalog)?;
    Ok(catalog)
}

/// Post-parse validation. Split out so callers that construct a
/// catalog programmatically (tests, future GUI editor, future
/// JSON-import path) can validate without going through TOML.
pub fn validate_catalog(c: &SkillCatalog) -> Result<(), CatalogError> {
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (idx, entry) in c.entries.iter().enumerate() {
        if entry.name.trim().is_empty() {
            return Err(CatalogError::EmptyName { idx });
        }
        if entry.description.trim().is_empty() {
            return Err(CatalogError::EmptyDescription { idx });
        }
        if entry.category.trim().is_empty() {
            return Err(CatalogError::EmptyCategory { idx });
        }
        if let Some(url) = &entry.url {
            if !is_http_url(url) {
                return Err(CatalogError::InvalidUrlScheme {
                    idx,
                    got: url.clone(),
                });
            }
        }
        if let Some(prior) = seen.insert(entry.name.clone(), idx) {
            return Err(CatalogError::DuplicateName {
                name: entry.name.clone(),
                first_idx: prior,
            });
        }
    }
    Ok(())
}

fn is_http_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

impl SkillCatalog {
    /// Count entries — convenience for the CLI summary line.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up one entry by exact `name`. None when missing.
    /// O(n) — the catalog is hand-curated + bounded; a HashMap
    /// build-then-query would lose insertion order.
    pub fn find(&self, name: &str) -> Option<&SkillEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Filter entries by category prefix (e.g. `cli` matches
    /// `cli/search` + `cli/files`). Returns refs in source order.
    pub fn by_category_prefix(&self, prefix: &str) -> Vec<&SkillEntry> {
        self.entries
            .iter()
            .filter(|e| e.category == prefix || e.category.starts_with(&format!("{prefix}/")))
            .collect()
    }

    /// Sorted set of every distinct tag in the catalog (lowercased
    /// per [`parse_catalog`]). Useful for the `neoth bosk tags`
    /// summary surface.
    pub fn all_tags(&self) -> Vec<String> {
        let set: HashSet<&str> = self
            .entries
            .iter()
            .flat_map(|e| e.tags.iter().map(String::as_str))
            .collect();
        let mut out: Vec<String> = set.into_iter().map(String::from).collect();
        out.sort();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_empty_catalog_with_no_entries() {
        let cat = parse_catalog(b"").unwrap();
        assert!(cat.is_empty());
        assert!(cat.meta.is_none());
    }

    #[test]
    fn parses_minimal_entry() {
        let toml = br#"
[[entry]]
name = "ripgrep"
category = "cli/search"
description = "Fast recursive grep replacement"
"#;
        let cat = parse_catalog(toml).unwrap();
        assert_eq!(cat.len(), 1);
        let e = &cat.entries[0];
        assert_eq!(e.name, "ripgrep");
        assert_eq!(e.category, "cli/search");
        assert_eq!(e.description, "Fast recursive grep replacement");
        assert!(e.url.is_none());
        assert!(e.install.is_none());
        assert!(e.tags.is_empty());
    }

    #[test]
    fn parses_full_entry_with_every_optional_field() {
        let toml = br#"
[meta]
title = "Operator Toolbox"
source_url = "https://github.com/trimstray/the-book-of-secret-knowledge"
version = "2026-05"
upstream_revision = "abc123"

[[entry]]
name = "fd"
category = "cli/files"
description = "Simple, fast user-friendly alternative to find"
url = "https://github.com/sharkdp/fd"
install = "cargo install fd-find"
tags = ["CLI", "filesystem", "Rust"]
"#;
        let cat = parse_catalog(toml).unwrap();
        let meta = cat.meta.as_ref().unwrap();
        assert_eq!(meta.title.as_deref(), Some("Operator Toolbox"));
        assert_eq!(meta.version.as_deref(), Some("2026-05"));

        let e = &cat.entries[0];
        assert_eq!(e.url.as_deref(), Some("https://github.com/sharkdp/fd"));
        assert_eq!(e.install.as_deref(), Some("cargo install fd-find"));
        // Tags must be lowercased by parse_catalog.
        assert_eq!(e.tags, vec!["cli", "filesystem", "rust"]);
    }

    #[test]
    fn rejects_entry_with_empty_name() {
        let toml = br#"
[[entry]]
name = ""
category = "x"
description = "y"
"#;
        let r = parse_catalog(toml);
        assert!(matches!(r, Err(CatalogError::EmptyName { idx: 0 })));
    }

    #[test]
    fn rejects_entry_with_whitespace_only_description() {
        let toml = br#"
[[entry]]
name = "x"
category = "y"
description = "   "
"#;
        let r = parse_catalog(toml);
        assert!(matches!(r, Err(CatalogError::EmptyDescription { idx: 0 })));
    }

    #[test]
    fn rejects_entry_with_empty_category() {
        let toml = br#"
[[entry]]
name = "x"
category = ""
description = "y"
"#;
        let r = parse_catalog(toml);
        assert!(matches!(r, Err(CatalogError::EmptyCategory { idx: 0 })));
    }

    #[test]
    fn rejects_duplicate_entry_names() {
        let toml = br#"
[[entry]]
name = "fd"
category = "cli/files"
description = "fast find"

[[entry]]
name = "ripgrep"
category = "cli/search"
description = "fast grep"

[[entry]]
name = "fd"
category = "cli/files"
description = "second collision"
"#;
        let r = parse_catalog(toml);
        match r {
            Err(CatalogError::DuplicateName { name, first_idx }) => {
                assert_eq!(name, "fd");
                assert_eq!(first_idx, 0);
            }
            other => panic!("expected DuplicateName, got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_http_url() {
        for bad_url in &["javascript:alert(1)", "ftp://example", "/local/path", ""] {
            let toml = format!(
                r#"
[[entry]]
name = "x"
category = "y"
description = "z"
url = "{bad_url}"
"#,
            );
            let r = parse_catalog(toml.as_bytes());
            assert!(
                matches!(r, Err(CatalogError::InvalidUrlScheme { .. })),
                "expected InvalidUrlScheme for url `{bad_url}`, got {r:?}",
            );
        }
    }

    #[test]
    fn accepts_http_and_https_urls() {
        for ok_url in &["http://example.com", "https://example.com/path?q=1"] {
            let toml = format!(
                r#"
[[entry]]
name = "x"
category = "y"
description = "z"
url = "{ok_url}"
"#,
            );
            assert!(parse_catalog(toml.as_bytes()).is_ok(), "should accept {ok_url}");
        }
    }

    #[test]
    fn find_returns_exact_match_only() {
        let toml = br#"
[[entry]]
name = "fd"
category = "cli/files"
description = "a"

[[entry]]
name = "ripgrep"
category = "cli/search"
description = "b"
"#;
        let cat = parse_catalog(toml).unwrap();
        assert_eq!(cat.find("fd").unwrap().description, "a");
        assert_eq!(cat.find("ripgrep").unwrap().description, "b");
        assert!(cat.find("FD").is_none(), "find is case-sensitive on name");
        assert!(cat.find("ag").is_none());
    }

    #[test]
    fn by_category_prefix_matches_exact_and_subpath() {
        let toml = br#"
[[entry]]
name = "fd"
category = "cli/files"
description = "a"

[[entry]]
name = "ripgrep"
category = "cli/search"
description = "b"

[[entry]]
name = "ninja"
category = "dev/build"
description = "c"
"#;
        let cat = parse_catalog(toml).unwrap();
        let cli = cat.by_category_prefix("cli");
        assert_eq!(cli.len(), 2);
        assert!(cli.iter().any(|e| e.name == "fd"));
        assert!(cli.iter().any(|e| e.name == "ripgrep"));
        let cli_search = cat.by_category_prefix("cli/search");
        assert_eq!(cli_search.len(), 1);
        assert_eq!(cli_search[0].name, "ripgrep");
    }

    #[test]
    fn all_tags_returns_sorted_distinct_set() {
        let toml = br#"
[[entry]]
name = "a"
category = "x"
description = "a"
tags = ["RUST", "cli", "search"]

[[entry]]
name = "b"
category = "x"
description = "b"
tags = ["go", "cli", "Network"]
"#;
        let cat = parse_catalog(toml).unwrap();
        // Tags lowercased on parse, deduped via HashSet, sorted on return.
        assert_eq!(
            cat.all_tags(),
            vec!["cli", "go", "network", "rust", "search"],
        );
    }

    #[test]
    fn parse_error_surfaces_with_context() {
        let r = parse_catalog(b"not = [valid toml");
        assert!(matches!(r, Err(CatalogError::Parse(_))));
    }
}
