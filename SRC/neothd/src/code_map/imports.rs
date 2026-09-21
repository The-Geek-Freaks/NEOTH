//! Conservative repository-local import graph.
//!
//! This is deliberately not a compiler or Python interpreter resolver.  It
//! records only import forms whose destination is one unambiguous scanned file
//! in the same canonical repository root.  Aliases, globs, re-exports,
//! `#[path]`, macro-generated modules and unresolved external packages are
//! omitted rather than guessed.  Consumers must interpret absence as unknown.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use syn::UseTree;

use super::walker::Language;

pub const DEFAULT_MAX_IMPORT_EDGES: usize = 100_000;
pub const DEFAULT_MAX_IMPORT_QUERY_NODES: usize = 10_000;
pub const DEFAULT_MAX_IMPORT_QUERY_TEXT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_IMPORT_SOURCE_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_IMPORT_FILE_SOURCE_BYTES: usize = super::walker::DEFAULT_MAX_FILE_BYTES as usize;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ImportEdge {
    pub from_file: String,
    pub to_file: String,
    pub language: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportDirection {
    #[default]
    Forward,
    Reverse,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImportEntry {
    pub file: String,
    pub depth: usize,
}

#[derive(Clone, Debug, Default)]
pub struct ImportGraph {
    edges: Vec<ImportEdge>,
    forward: BTreeMap<String, Vec<String>>,
    reverse: BTreeMap<String, Vec<String>>,
}

impl ImportGraph {
    pub fn from_edges(mut edges: Vec<ImportEdge>) -> Self {
        // This in-memory constructor deliberately drops malformed endpoints;
        // persistence performs the stronger current-snapshot membership check.
        edges.retain(|edge| {
            valid_repo_relative_path(&edge.from_file)
                && valid_repo_relative_path(&edge.to_file)
                && edge.from_file != edge.to_file
                && !edge.language.is_empty()
        });
        edges.sort();
        edges.dedup();
        let mut graph = Self { edges, ..Self::default() };
        for edge in &graph.edges {
            graph.forward.entry(edge.from_file.clone()).or_default().push(edge.to_file.clone());
            graph.reverse.entry(edge.to_file.clone()).or_default().push(edge.from_file.clone());
        }
        for adjacent in graph.forward.values_mut().chain(graph.reverse.values_mut()) {
            adjacent.sort();
            adjacent.dedup();
        }
        graph
    }

    pub fn edges(&self) -> &[ImportEdge] { &self.edges }

    /// `sources` must be exactly the byte/hash-validated scan corpus.  The
    /// resolver is lexical but the candidate universe is root-local and exact.
    pub fn build_bounded(
        sources: &[(String, Language, String)],
        max_edges: usize,
    ) -> Result<Self> {
        let paths: BTreeSet<String> = sources.iter().map(|(path, _, _)| path.clone()).collect();
        let mut edges = Vec::new();
        let mut source_bytes = 0usize;
        for (path, language, source) in sources {
            ensure!(
                valid_repo_relative_path(path),
                "import source path is not a normalized repository-relative path"
            );
            ensure!(
                source.len() <= MAX_IMPORT_FILE_SOURCE_BYTES,
                "import source {} exceeds bounded {}-byte per-file budget",
                path,
                MAX_IMPORT_FILE_SOURCE_BYTES
            );
            source_bytes = source_bytes.checked_add(source.len()).ok_or_else(|| anyhow::anyhow!("import source byte count overflow"))?;
            ensure!(
                source_bytes <= MAX_IMPORT_SOURCE_BYTES,
                "import graph source exceeds bounded {MAX_IMPORT_SOURCE_BYTES}-byte work budget"
            );
            let resolved = match language {
                Language::Rust => resolve_rust_imports(path, source, &paths),
                Language::Python => resolve_python_imports(path, source, &paths),
                _ => Vec::new(),
            };
            for target in resolved {
                if target == *path { continue; }
                ensure!(paths.contains(&target), "import resolver emitted non-snapshot path");
                if edges.len() >= max_edges {
                    bail!("import graph exceeds bounded {max_edges}-edge publish cap");
                }
                edges.push(ImportEdge {
                    from_file: path.clone(),
                    to_file: target,
                    language: import_language(*language).to_owned(),
                });
            }
        }
        Ok(Self::from_edges(edges))
    }

    pub fn query_bounded(
        &self,
        file: &str,
        direction: ImportDirection,
        max_depth: usize,
        max_nodes: usize,
        max_text_bytes: usize,
    ) -> Result<Vec<ImportEntry>> {
        if max_depth == 0 { return Ok(Vec::new()); }
        let adjacency = match direction { ImportDirection::Forward => &self.forward, ImportDirection::Reverse => &self.reverse };
        let mut queue = VecDeque::from([(file.to_owned(), 0usize)]);
        let mut seen = BTreeSet::from([file.to_owned()]);
        let mut out = Vec::new();
        let mut text_bytes = 0usize;
        while let Some((node, depth)) = queue.pop_front() {
            if depth >= max_depth { continue; }
            for next in adjacency.get(&node).into_iter().flatten() {
                if !seen.insert(next.clone()) { continue; }
                if out.len() >= max_nodes { bail!("import graph query exceeds bounded {max_nodes}-node budget"); }
                text_bytes = text_bytes.checked_add(next.len()).ok_or_else(|| anyhow::anyhow!("import graph query text byte count overflow"))?;
                if text_bytes > max_text_bytes { bail!("import graph query exceeds bounded {max_text_bytes}-byte text budget"); }
                let next_depth = depth + 1;
                out.push(ImportEntry { file: next.clone(), depth: next_depth });
                queue.push_back((next.clone(), next_depth));
            }
        }
        out.sort_by(|a, b| a.depth.cmp(&b.depth).then_with(|| a.file.cmp(&b.file)));
        Ok(out)
    }
}

fn import_language(language: Language) -> &'static str {
    match language { Language::Rust => "rust", Language::Python => "python", _ => "unknown" }
}

fn resolve_rust_imports(path: &str, source: &str, paths: &BTreeSet<String>) -> Vec<String> {
    let mut targets = BTreeSet::new();
    let module_dir = rust_module_dir(path);
    // `syn` is already the code-map Rust parser. Parsing top-level items
    // avoids lexical false edges from comments, strings and raw strings. We
    // intentionally do not infer nested-module context in this slice.
    let Ok(file) = syn::parse_file(source) else { return Vec::new(); };
    for item in &file.items {
        if let syn::Item::Mod(module) = item {
            let has_path_override = module.attrs.iter().any(|attr| attr.path().is_ident("path"));
            if module.content.is_none() && !has_path_override && is_simple_identifier(&module.ident.to_string()) {
                let name = module.ident.to_string();
                add_unique_module_target(&mut targets, &module_dir, &[&name], paths);
            }
            continue;
        }
        let syn::Item::Use(use_item) = item else { continue; };
        let mut owned_parts = Vec::new();
        if !simple_use_segments(&use_item.tree, &mut owned_parts) { continue; }
        let parts: Vec<&str> = owned_parts.iter().map(String::as_str).collect();
        if parts.is_empty() { continue; }
        let (base, tail) = match parts[0] {
            "crate" => (rust_crate_root(path, paths), &parts[1..]),
            "self" => (module_dir.clone(), &parts[1..]),
            "super" => (parent_dir(&module_dir), &parts[1..]),
            _ => continue,
        };
        if tail.is_empty() { continue; }
        // `use crate::a::Thing` may denote module a plus item Thing.  Resolve
        // only an exact unique module prefix; a final item is never invented.
        for end in (1..=tail.len()).rev() {
            let before = targets.len();
            add_unique_module_target(&mut targets, &base, &tail[..end], paths);
            if targets.len() > before { break; }
        }
    }
    targets.into_iter().collect()
}

fn simple_use_segments(tree: &UseTree, segments: &mut Vec<String>) -> bool {
    match tree {
        UseTree::Path(path) => {
            segments.push(path.ident.to_string());
            simple_use_segments(&path.tree, segments)
        }
        UseTree::Name(name) => { segments.push(name.ident.to_string()); true }
        // Rename, glob and group resolution needs compiler name resolution;
        // never turn those syntactic candidates into local graph evidence.
        UseTree::Rename(_) | UseTree::Glob(_) | UseTree::Group(_) => false,
    }
}

fn rust_crate_root(path: &str, paths: &BTreeSet<String>) -> String {
    let mut current = parent_dir(path);
    loop {
        let lib = join_path(&current, "lib.rs");
        let main = join_path(&current, "main.rs");
        if paths.contains(&lib) || paths.contains(&main) { return current; }
        let parent = parent_dir(&current);
        if parent == current { return String::new(); }
        current = parent;
    }
}

fn rust_module_dir(path: &str) -> String {
    let parent = parent_dir(path);
    if path.ends_with("/lib.rs")
        || path.ends_with("/main.rs")
        || path.ends_with("/mod.rs")
        || matches!(path, "lib.rs" | "main.rs" | "mod.rs")
    {
        parent
    } else {
        // Rust's conventional out-of-line children of `foo.rs` live under
        // `foo/`; resolving them beside the file would cross-link modules.
        let stem = path.rsplit_once('/').map_or(path, |(_, name)| name).strip_suffix(".rs").unwrap_or_default();
        join_path(&parent, stem)
    }
}

fn add_unique_module_target(targets: &mut BTreeSet<String>, base: &str, segments: &[&str], paths: &BTreeSet<String>) {
    let relative = segments.join("/");
    let file = join_path(base, &(relative.clone() + ".rs"));
    let module = join_path(base, &(relative + "/mod.rs"));
    match (paths.contains(&file), paths.contains(&module)) {
        (true, false) => { targets.insert(file); }
        (false, true) => { targets.insert(module); }
        _ => {}
    }
}

fn resolve_python_imports(path: &str, source: &str, paths: &BTreeSet<String>) -> Vec<String> {
    let mut targets = BTreeSet::new();
    // Reuse the existing Python-family neutralizer instead of attempting a
    // second string/comment lexer. It preserves line shape while removing
    // comments, quotes and triple-quoted bodies before lexical import checks.
    let stripped = super::graph::strip_comments_and_strings_hash_family(source);
    for line in stripped.lines() {
        let line = line.trim();
        if line.starts_with('#') { continue; }
        if let Some(module) = line.strip_prefix("import ") {
            if module.contains(',') || module.contains(" as ") { continue; }
            add_unique_python_module(&mut targets, module.trim(), paths);
        } else if let Some(rest) = line.strip_prefix("from ") {
            let Some((module, imported)) = rest.split_once(" import ") else { continue; };
            if imported.contains(',') || imported.contains('*') || imported.contains(" as ") { continue; }
            if module.starts_with('.') {
                let levels = module.bytes().take_while(|byte| *byte == b'.').count();
                let suffix = &module[levels..];
                let mut base = parent_dir(path);
                for _ in 1..levels { base = parent_dir(&base); }
                // `from .sub import Thing` imports module `sub`, whereas
                // `from . import sub` imports module `sub`; `Thing` is never
                // appended to a non-empty module path as a fake file edge.
                let name = if suffix.is_empty() { imported.trim().to_owned() } else { suffix.to_owned() };
                add_unique_python_relative(&mut targets, &base, &name, paths);
            } else {
                // Absolute imports are accepted only if the module spelling
                // maps to exactly one scanned module; no src-layout guessing.
                add_unique_python_module(&mut targets, module.trim(), paths);
            }
        }
    }
    targets.into_iter().collect()
}

fn add_unique_python_module(targets: &mut BTreeSet<String>, module: &str, paths: &BTreeSet<String>) {
    if !module.split('.').all(is_simple_identifier) { return; }
    let suffix = module.replace('.', "/");
    let candidates: Vec<String> = paths.iter().filter(|path| **path == format!("{suffix}.py") || **path == format!("{suffix}/__init__.py")).cloned().collect();
    if candidates.len() == 1 { targets.insert(candidates[0].clone()); }
}

fn add_unique_python_relative(targets: &mut BTreeSet<String>, base: &str, module: &str, paths: &BTreeSet<String>) {
    if !module.split('.').all(is_simple_identifier) { return; }
    let suffix = module.replace('.', "/");
    let file = join_path(base, &(suffix.clone() + ".py"));
    let package = join_path(base, &(suffix + "/__init__.py"));
    match (paths.contains(&file), paths.contains(&package)) {
        (true, false) => { targets.insert(file); }
        (false, true) => { targets.insert(package); }
        _ => {}
    }
}

fn is_simple_identifier(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte == b'_' || byte.is_ascii_alphanumeric()) && !value.bytes().next().is_some_and(|byte| byte.is_ascii_digit())
}
fn valid_repo_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\\')
        && !std::path::Path::new(path).is_absolute()
        && std::path::Path::new(path).components().all(|component| {
            matches!(component, std::path::Component::Normal(_))
        })
}
fn parent_dir(path: &str) -> String { path.rsplit_once('/').map_or_else(String::new, |(parent, _)| parent.to_owned()) }
fn join_path(base: &str, leaf: &str) -> String { if base.is_empty() { leaf.to_owned() } else { format!("{base}/{leaf}") } }

#[cfg(test)]
mod tests {
    use super::*;
    fn sources(rows: &[(&str, Language, &str)]) -> Vec<(String, Language, String)> { rows.iter().map(|(p, l, s)| ((*p).into(), *l, (*s).into())).collect() }
    #[test]
    fn resolves_only_unambiguous_root_local_rust_and_python_modules() {
        let graph = ImportGraph::build_bounded(&sources(&[
            ("a/src/lib.rs", Language::Rust, "mod api; use crate::api::Client;"),
            ("a/src/api.rs", Language::Rust, ""),
            ("a/src/parent.rs", Language::Rust, "mod child;"),
            ("a/src/parent/child.rs", Language::Rust, ""),
            ("pkg/main.py", Language::Python, "from . import helper\nfrom .sub import Thing"),
            ("pkg/helper.py", Language::Python, ""),
            ("pkg/sub.py", Language::Python, ""),
        ]), 10).unwrap();
        assert!(graph.edges().iter().any(|edge| edge.from_file == "a/src/lib.rs" && edge.to_file == "a/src/api.rs"));
        assert!(graph.edges().iter().any(|edge| edge.from_file == "a/src/parent.rs" && edge.to_file == "a/src/parent/child.rs"));
        assert!(graph.edges().iter().any(|edge| edge.from_file == "pkg/main.py" && edge.to_file == "pkg/helper.py"));
        assert!(graph.edges().iter().any(|edge| edge.from_file == "pkg/main.py" && edge.to_file == "pkg/sub.py"));
    }
    #[test]
    fn does_not_crosslink_duplicate_monorepo_module_or_guess_aliases() {
        let graph = ImportGraph::build_bounded(&sources(&[
            ("one/src/lib.rs", Language::Rust, "use crate::util as u;"),
            ("one/src/util.rs", Language::Rust, ""),
            ("two/src/lib.rs", Language::Rust, ""),
            ("two/src/util.rs", Language::Rust, ""),
            ("app.py", Language::Python, "import util"),
            ("one/util.py", Language::Python, ""),
            ("two/util.py", Language::Python, ""),
        ]), 10).unwrap();
        assert!(graph.edges().is_empty());
    }
    #[test]
    fn ignores_rust_and_python_import_lookalikes_in_comments_and_strings() {
        let graph = ImportGraph::build_bounded(&sources(&[
            ("src/lib.rs", Language::Rust, "// mod fake;\nconst S: &str = \"use crate::fake;\";"),
            ("src/fake.rs", Language::Rust, ""),
            ("main.py", Language::Python, "# import fake\ndoc = '''\nimport fake\n'''\n"),
            ("fake.py", Language::Python, ""),
        ]), 10).unwrap();
        assert!(graph.edges().is_empty());
    }
    #[test]
    fn bounded_query_terminates_cycles_and_refuses_node_or_text_overflow() {
        let graph = ImportGraph::from_edges(vec![
            ImportEdge { from_file: "a.rs".into(), to_file: "b.rs".into(), language: "rust".into() },
            ImportEdge { from_file: "b.rs".into(), to_file: "a.rs".into(), language: "rust".into() },
        ]);
        assert_eq!(graph.query_bounded("a.rs", ImportDirection::Forward, 4, 4, 100).unwrap().len(), 1);
        assert!(graph.query_bounded("a.rs", ImportDirection::Forward, 4, 0, 100).is_err());
        assert!(graph.query_bounded("a.rs", ImportDirection::Forward, 4, 4, 1).is_err());
    }
    #[test]
    fn rejects_or_drops_noncanonical_import_endpoints_before_graph_use() {
        let graph = ImportGraph::from_edges(vec![ImportEdge {
            from_file: "src/a.rs".into(), to_file: "../outside.rs".into(), language: "rust".into(),
        }]);
        assert!(graph.edges().is_empty());
        assert!(ImportGraph::build_bounded(
            &sources(&[("../a.rs", Language::Rust, "")]), 1,
        ).is_err());
    }
}
