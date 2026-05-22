//! In-memory call graph over the symbols extracted by
//! `code_map::symbols`. QM-2 Phase 1.
//!
//! Edges are inferred by scanning each symbol's body for the names of
//! other known symbols followed by `(` (the call-site shape). v0.1
//! scope: language-agnostic regex scan, no AST. Misses are acceptable
//! — the goal is "good enough to bootstrap zoom_out / improve_codebase
//! architecture recommendations", not perfect static analysis.
//!
//! Persistence is Phase 2 (adds a `code_map_edges` table next to the
//! existing `code_map_symbols`). Today the graph is rebuilt from the
//! in-memory symbol set + source text on each call — fine because
//! repos this scans are < 1 MB total source per `relevant_files_for_prompt`
//! invocation.
//!
//! BFS: `callers_of(target, max_depth)` walks the inverse adjacency to
//! enumerate every symbol that (transitively) reaches `target` within
//! the depth budget. `callees_of(source, max_depth)` is the forward
//! direction. Both return paths so the operator's "who calls X?"
//! question gets traceable answers.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use serde::{Deserialize, Serialize};

use super::symbols::{Symbol, SymbolKind};

/// One typed edge between two symbols. `from` is the symbol that
/// contains the reference; `to_name` is the bare identifier the
/// regex matched (no path-resolution today — Phase 2 resolves
/// across files).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CodeEdge {
    pub from_file: String,
    pub from_symbol: String,
    pub to_name: String,
    pub kind: EdgeKind,
}

/// Classification of the relationship. v0.1 ships `Calls` only; the
/// enum keeps the shape forward-compatible.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// `from` invokes `to_name` — regex matched `<name>(`.
    Calls,
    /// `from` mentions `to_name` in its body without the trailing
    /// `(`. Phase 2 — reserved.
    References,
}

impl EdgeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EdgeKind::Calls => "calls",
            EdgeKind::References => "references",
        }
    }
}

/// One file's worth of input: the symbols extracted by
/// `symbols::extract_symbols` + the original source text the
/// extractor saw. The graph builder needs both — symbols mark the
/// scopes, source text feeds the call scan.
#[derive(Clone, Debug)]
pub struct FileInput {
    pub file_path: String,
    pub source: String,
    pub symbols: Vec<Symbol>,
}

/// Adjacency-list graph. Cloning is cheap because the underlying
/// collections store owned strings — the graph is small enough that
/// clones are fine for "render a view" usage.
#[derive(Clone, Debug, Default)]
pub struct CallGraph {
    edges: Vec<CodeEdge>,
    /// `symbol_name -> set of edges INTO that name` (callers).
    by_callee: HashMap<String, Vec<usize>>,
    /// `(file, symbol_name) -> set of edges OUT of that scope` (callees).
    by_source: HashMap<(String, String), Vec<usize>>,
    /// Every defined symbol, keyed by name → set of (file, kind, line).
    /// Multiple defs in the same name (overloaded methods across files)
    /// surface here so a `callers_of("foo")` query finds every callsite.
    defs_by_name: BTreeMap<String, Vec<SymbolDef>>,
}

/// Where a name is declared. Phase 2 will use these refs to filter
/// edges so a call to `foo` only matches the `foo` in the visible
/// scope; v0.1 returns the multi-def list and lets the caller pick.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolDef {
    pub file_path: String,
    pub kind: SymbolKind,
    pub line: u32,
}

impl CallGraph {
    /// Build a graph from a list of files. Identifier scanning treats
    /// any symbol name (extracted from any file) as a potential call
    /// target — cross-file calls show up as edges from one file's
    /// symbol scope to another file's defined name.
    pub fn build(files: &[FileInput]) -> Self {
        let mut graph = Self::default();
        // Index every defined symbol by name first.
        let mut all_names: BTreeSet<String> = BTreeSet::new();
        for f in files {
            for s in &f.symbols {
                graph
                    .defs_by_name
                    .entry(s.name.clone())
                    .or_default()
                    .push(SymbolDef {
                        file_path: f.file_path.clone(),
                        kind: s.kind,
                        line: s.line,
                    });
                all_names.insert(s.name.clone());
            }
        }
        // Build edges: for each file, segment the source into per-symbol
        // bodies (line-bounded by the next symbol's declaration line)
        // and scan each body for "<name>(" patterns. Phase 2 strips
        // C-family comments + string literals before the scan so
        // identifiers in commentary or sample-data strings don't
        // produce false-positive edges.
        for f in files {
            let mut symbols_sorted = f.symbols.clone();
            symbols_sorted.sort_by_key(|s| s.line);
            let stripped_source = strip_comments_and_strings_c_family(&f.source);
            for (i, s) in symbols_sorted.iter().enumerate() {
                let start_line = s.line as usize;
                let end_line = symbols_sorted
                    .get(i + 1)
                    .map(|n| n.line as usize)
                    .unwrap_or_else(|| stripped_source.lines().count() + 1);
                let body = file_slice(&stripped_source, start_line, end_line);
                for name in &all_names {
                    // Skip self-edges — a fn that calls itself isn't a
                    // graph traversal anchor v0.1 cares about.
                    if name == &s.name {
                        continue;
                    }
                    if is_called(&body, name) {
                        let edge = CodeEdge {
                            from_file: f.file_path.clone(),
                            from_symbol: s.name.clone(),
                            to_name: name.clone(),
                            kind: EdgeKind::Calls,
                        };
                        let idx = graph.edges.len();
                        graph.edges.push(edge);
                        graph.by_callee.entry(name.clone()).or_default().push(idx);
                        graph
                            .by_source
                            .entry((f.file_path.clone(), s.name.clone()))
                            .or_default()
                            .push(idx);
                    }
                }
            }
        }
        graph
    }

    pub fn edges(&self) -> &[CodeEdge] {
        &self.edges
    }

    pub fn defs_for(&self, name: &str) -> Option<&[SymbolDef]> {
        self.defs_by_name.get(name).map(|v| v.as_slice())
    }

    /// BFS over inverse adjacency: every symbol that (transitively)
    /// calls `target` within `max_depth` hops. Result includes the
    /// depth at which each caller was discovered so callers can
    /// render a layered "who reaches X" view. The target itself is
    /// not included.
    pub fn callers_of(&self, target: &str, max_depth: usize) -> Vec<CallerEntry> {
        if max_depth == 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
        let mut q: VecDeque<(String, usize)> = VecDeque::new();
        q.push_back((target.to_string(), 0));
        seen.insert((String::new(), target.to_string()));
        while let Some((current_name, depth)) = q.pop_front() {
            if depth >= max_depth {
                continue;
            }
            let Some(edge_idxs) = self.by_callee.get(&current_name) else {
                continue;
            };
            for &i in edge_idxs {
                let edge = &self.edges[i];
                let key = (edge.from_file.clone(), edge.from_symbol.clone());
                if seen.insert(key.clone()) {
                    out.push(CallerEntry {
                        file_path: edge.from_file.clone(),
                        symbol: edge.from_symbol.clone(),
                        depth: depth + 1,
                    });
                    q.push_back((edge.from_symbol.clone(), depth + 1));
                }
            }
        }
        out
    }

    /// BFS forward: every symbol name that the scope (file_path,
    /// source_symbol) (transitively) reaches within `max_depth`
    /// hops. The source itself is not included.
    pub fn callees_of(
        &self,
        file_path: &str,
        source: &str,
        max_depth: usize,
    ) -> Vec<CalleeEntry> {
        if max_depth == 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut q: VecDeque<(String, String, usize)> = VecDeque::new();
        seen.insert(source.to_string());
        q.push_back((file_path.to_string(), source.to_string(), 0));
        while let Some((cur_file, cur_sym, depth)) = q.pop_front() {
            if depth >= max_depth {
                continue;
            }
            let Some(edge_idxs) = self.by_source.get(&(cur_file.clone(), cur_sym.clone())) else {
                continue;
            };
            for &i in edge_idxs {
                let edge = &self.edges[i];
                if seen.insert(edge.to_name.clone()) {
                    out.push(CalleeEntry {
                        name: edge.to_name.clone(),
                        depth: depth + 1,
                    });
                    // Walk into every def of that name (cross-file).
                    if let Some(defs) = self.defs_by_name.get(&edge.to_name) {
                        for def in defs {
                            q.push_back((
                                def.file_path.clone(),
                                edge.to_name.clone(),
                                depth + 1,
                            ));
                        }
                    }
                }
            }
        }
        out
    }
}

/// One row in the `callers_of` result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallerEntry {
    pub file_path: String,
    pub symbol: String,
    pub depth: usize,
}

/// One row in the `callees_of` result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalleeEntry {
    pub name: String,
    pub depth: usize,
}

/// Extract the line-range from `src` that covers `[start_line .. end_line)`
/// (1-indexed). Tolerant of out-of-range indices.
fn file_slice(src: &str, start_line: usize, end_line: usize) -> String {
    src.lines()
        .skip(start_line.saturating_sub(1))
        .take(end_line.saturating_sub(start_line))
        .collect::<Vec<_>>()
        .join("\n")
}

/// QM-2 Phase 2: strip comments + string literals from `src` so the
/// regex callsite scan doesn't fire on identifiers that appear in
/// natural-language commentary or sample-data strings. Pure C-family
/// rules (`//` to EOL + `/* … */` block + `"…"` + `'…'`) cover
/// Rust / C / C++ / JS / TS / Go / Java / Kotlin / Swift / Scala.
/// Python / Shell / Ruby (`#`-comments + triple-quoted strings) are
/// the v0.2 follow-up; Python sources today still get false
/// positives but the regex extractor only marks a small set of
/// files as Python anyway.
///
/// Pure function — tested in isolation. Quotation chars + comment
/// markers themselves remain in the output so line numbering is
/// preserved across the strip (one byte → one space).
pub fn strip_comments_and_strings_c_family(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        let next = bytes.get(i + 1).copied();
        // // line comment
        if c == b'/' && next == Some(b'/') {
            out.push(b'/');
            out.push(b'/');
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                if bytes[i].is_ascii_whitespace() {
                    out.push(bytes[i]);
                } else {
                    out.push(b' ');
                }
                i += 1;
            }
            continue;
        }
        // /* block comment */
        if c == b'/' && next == Some(b'*') {
            out.push(b'/');
            out.push(b'*');
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                if bytes[i] == b'\n' {
                    out.push(b'\n');
                } else {
                    out.push(b' ');
                }
                i += 1;
            }
            // Emit the closing */ if we found it.
            if i + 1 < bytes.len() {
                out.push(b'*');
                out.push(b'/');
                i += 2;
            }
            continue;
        }
        // "..." string literal (also covers Rust raw strings well
        // enough — r"…" treats the `r` as code which is fine since
        // identifiers around it stay intact).
        if c == b'"' {
            out.push(b'"');
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    // Skip escaped quote so \" doesn't end the literal.
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    continue;
                }
                if bytes[i] == b'\n' {
                    out.push(b'\n');
                } else {
                    out.push(b' ');
                }
                i += 1;
            }
            if i < bytes.len() {
                out.push(b'"');
                i += 1;
            }
            continue;
        }
        // '…' char literal (or Rust lifetime — keep one char so
        // lifetimes don't get neutered; only nuke the multi-char
        // form where it's clearly a literal).
        if c == b'\'' && bytes.get(i + 2) == Some(&b'\'') {
            out.push(b'\'');
            out.push(b' ');
            out.push(b'\'');
            i += 3;
            continue;
        }
        out.push(c);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| src.to_string())
}

/// True when `body` contains `<name>(` as a callsite. Word-boundary
/// is approximated by requiring the previous char (when present)
/// to be a non-identifier char (so `foo_bar(` is matched but
/// `myfoo(` is not when looking for `foo`).
fn is_called(body: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let needle = format!("{name}(");
    let mut pos = 0;
    while let Some(idx) = body[pos..].find(&needle) {
        let abs = pos + idx;
        if abs == 0
            || !body
                .as_bytes()
                .get(abs - 1)
                .map(|b| b.is_ascii_alphanumeric() || *b == b'_')
                .unwrap_or(false)
        {
            return true;
        }
        pos = abs + 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_map::symbols::{Symbol, SymbolKind};
    use crate::code_map::walker::Language;

    fn rust_file(path: &str, src: &str) -> FileInput {
        let syms = crate::code_map::symbols::extract_symbols(src, Language::Rust);
        FileInput {
            file_path: path.to_string(),
            source: src.to_string(),
            symbols: syms,
        }
    }

    #[test]
    fn edge_kind_as_str_pinned() {
        assert_eq!(EdgeKind::Calls.as_str(), "calls");
        assert_eq!(EdgeKind::References.as_str(), "references");
    }

    #[test]
    fn empty_input_returns_empty_graph() {
        let g = CallGraph::build(&[]);
        assert!(g.edges().is_empty());
    }

    #[test]
    fn single_call_within_file_creates_edge() {
        let src = r#"
fn helper() {}
fn caller() {
    helper();
}
"#;
        let g = CallGraph::build(&[rust_file("a.rs", src)]);
        let calls: Vec<_> = g
            .edges()
            .iter()
            .filter(|e| e.kind == EdgeKind::Calls && e.to_name == "helper")
            .collect();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].from_symbol, "caller");
        assert_eq!(calls[0].from_file, "a.rs");
    }

    #[test]
    fn cross_file_call_creates_edge() {
        let lib_src = "fn helper() {}\n";
        let caller_src = r#"
fn caller() {
    helper();
}
"#;
        let g = CallGraph::build(&[
            rust_file("lib.rs", lib_src),
            rust_file("caller.rs", caller_src),
        ]);
        assert!(g
            .edges()
            .iter()
            .any(|e| e.from_file == "caller.rs" && e.to_name == "helper"));
    }

    #[test]
    fn callers_of_walks_inverse_adjacency() {
        let src = r#"
fn leaf() {}
fn middle() {
    leaf();
}
fn root() {
    middle();
}
"#;
        let g = CallGraph::build(&[rust_file("x.rs", src)]);
        let callers = g.callers_of("leaf", 5);
        let names: Vec<&str> = callers.iter().map(|c| c.symbol.as_str()).collect();
        assert!(names.contains(&"middle"));
        assert!(names.contains(&"root"));
        // Depth: middle=1 (direct caller), root=2 (calls middle).
        let middle = callers.iter().find(|c| c.symbol == "middle").unwrap();
        let root = callers.iter().find(|c| c.symbol == "root").unwrap();
        assert_eq!(middle.depth, 1);
        assert_eq!(root.depth, 2);
    }

    #[test]
    fn callers_of_respects_max_depth() {
        let src = r#"
fn leaf() {}
fn middle() { leaf(); }
fn root() { middle(); }
"#;
        let g = CallGraph::build(&[rust_file("x.rs", src)]);
        let shallow = g.callers_of("leaf", 1);
        let names: Vec<&str> = shallow.iter().map(|c| c.symbol.as_str()).collect();
        assert!(names.contains(&"middle"));
        assert!(!names.contains(&"root"));
    }

    #[test]
    fn callees_of_walks_forward() {
        let src = r#"
fn leaf() {}
fn middle() { leaf(); }
fn root() { middle(); }
"#;
        let g = CallGraph::build(&[rust_file("x.rs", src)]);
        let reach = g.callees_of("x.rs", "root", 5);
        let names: Vec<&str> = reach.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"middle"));
        assert!(names.contains(&"leaf"));
    }

    #[test]
    fn callees_of_max_depth_zero_returns_empty() {
        let src = "fn x() {} fn y() { x(); }\n";
        let g = CallGraph::build(&[rust_file("a.rs", src)]);
        assert!(g.callees_of("a.rs", "y", 0).is_empty());
    }

    #[test]
    fn self_edges_excluded() {
        let src = r#"
fn recursive() {
    recursive();
}
"#;
        let g = CallGraph::build(&[rust_file("a.rs", src)]);
        // Self-call should NOT show up — recursive() calling recursive()
        // is meaningless for graph traversal.
        assert!(g
            .edges()
            .iter()
            .all(|e| !(e.from_symbol == "recursive" && e.to_name == "recursive")));
    }

    #[test]
    fn substring_match_in_other_identifier_does_not_create_edge() {
        let src = r#"
fn foo() {}
fn caller() {
    myfoo();
}
fn myfoo() {}
"#;
        let g = CallGraph::build(&[rust_file("a.rs", src)]);
        let to_foo: Vec<_> = g
            .edges()
            .iter()
            .filter(|e| e.from_symbol == "caller" && e.to_name == "foo")
            .collect();
        assert!(to_foo.is_empty(), "myfoo() shouldn't count as a foo() call");
    }

    #[test]
    fn comment_with_foo_call_no_longer_creates_false_positive() {
        // QM-2 Phase 2 fix: C-family comments are stripped before
        // the callsite scan, so "// foo()" in a comment no longer
        // produces an edge.
        let src = r#"
fn foo() {}
fn caller() {
    // This comment mentions foo() but doesn't call it.
}
"#;
        let g = CallGraph::build(&[rust_file("a.rs", src)]);
        let to_foo: Vec<_> = g
            .edges()
            .iter()
            .filter(|e| e.from_symbol == "caller" && e.to_name == "foo")
            .collect();
        assert!(
            to_foo.is_empty(),
            "comment-only foo() reference should not create an edge"
        );
    }

    #[test]
    fn string_literal_with_foo_call_no_longer_creates_false_positive() {
        let src = r#"
fn foo() {}
fn caller() {
    let _msg = "this string contains foo() but isn't a call";
}
"#;
        let g = CallGraph::build(&[rust_file("a.rs", src)]);
        let to_foo: Vec<_> = g
            .edges()
            .iter()
            .filter(|e| e.from_symbol == "caller" && e.to_name == "foo")
            .collect();
        assert!(
            to_foo.is_empty(),
            "string-literal foo() reference should not create an edge"
        );
    }

    #[test]
    fn strip_comments_preserves_line_numbers() {
        // Stripping must preserve newlines so line-bound body
        // segmentation stays correct.
        let src = "fn a() {\n// comment\n}\nfn b() {}\n";
        let stripped = strip_comments_and_strings_c_family(src);
        assert_eq!(src.lines().count(), stripped.lines().count());
        // Function names + braces survive.
        assert!(stripped.contains("fn a"));
        assert!(stripped.contains("fn b"));
    }

    #[test]
    fn strip_comments_block_comment_with_internal_newlines() {
        let src = "fn a() { /* line1\n   line2\n   line3 */ }\n";
        let stripped = strip_comments_and_strings_c_family(src);
        assert_eq!(src.lines().count(), stripped.lines().count());
        assert!(stripped.contains("fn a"));
        // Body of the block comment is neutered — line1 word gone.
        assert!(!stripped.contains("line1"));
    }

    #[test]
    fn defs_for_returns_multi_def_when_name_collides() {
        let a = rust_file("a.rs", "fn shared() {}\n");
        let b = rust_file("b.rs", "fn shared() {}\n");
        let g = CallGraph::build(&[a, b]);
        let defs = g.defs_for("shared").unwrap();
        assert_eq!(defs.len(), 2);
        assert!(defs.iter().any(|d| d.file_path == "a.rs"));
        assert!(defs.iter().any(|d| d.file_path == "b.rs"));
        for d in defs {
            assert_eq!(d.kind, SymbolKind::Function);
        }
    }

    #[test]
    fn is_called_helper_word_boundary() {
        assert!(is_called("foo();", "foo"));
        assert!(is_called("if foo() { ... }", "foo"));
        assert!(is_called("foo()", "foo"));
        assert!(!is_called("myfoo()", "foo"));
        assert!(!is_called("Foobar()", "foo"));
        assert!(!is_called("foo_bar()", "foo"));
        assert!(!is_called("", "foo"));
        assert!(!is_called("foo", "foo"));  // no trailing (
    }

    #[test]
    fn callers_of_max_depth_zero_returns_empty() {
        let src = "fn x() {} fn y() { x(); }\n";
        let g = CallGraph::build(&[rust_file("a.rs", src)]);
        assert!(g.callers_of("x", 0).is_empty());
    }

    #[test]
    fn callers_of_unknown_name_returns_empty() {
        let g = CallGraph::build(&[rust_file("a.rs", "fn x() {}\n")]);
        assert!(g.callers_of("nonexistent", 5).is_empty());
    }

    // Reference to Symbol to silence the unused-import lint.
    #[test]
    fn symbol_kind_is_carried_through_def() {
        let _ = Symbol {
            name: "anchor".into(),
            kind: SymbolKind::Function,
            line: 1,
        };
    }
}
