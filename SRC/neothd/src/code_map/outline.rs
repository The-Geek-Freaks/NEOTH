//! GOLD-ADAPT-CCS-04 — per-file AST outline.
//!
//! Produces a structural overview of a source file: each top-level
//! declaration (function, struct, trait, class, …) with its start line
//! and an estimated end line. Uses the existing regex-based
//! [`extract_symbols`] machinery — **no new Cargo dependencies**.
//!
//! ## Line-range estimation
//!
//! A full AST parse is the Phase 2b tree-sitter follow-up. Here the
//! end line of symbol N is estimated as `line_start(N+1) - 1`, clamped
//! to the total line count for the last symbol. This is exact for
//! top-level declarations with no blank lines between them and a
//! conservative lower-bound otherwise — sufficient for the
//! token-saving overview use case.
//!
//! ## Output shape
//!
//! ```json
//! [
//!   { "name": "Foo",  "kind": "struct",   "line_start": 3,  "line_end": 12 },
//!   { "name": "bar",  "kind": "function", "line_start": 14, "line_end": 28 }
//! ]
//! ```

use serde::{Deserialize, Serialize};

use super::symbols::{Symbol, SymbolKind, extract_symbols};
use super::walker::Language;

/// One entry in the structural outline of a file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutlineEntry {
    /// Bare identifier name (no generics, no module path).
    pub name: String,
    /// Coarse symbol kind (function, struct, trait, …).
    pub kind: SymbolKind,
    /// 1-indexed line where the declaration begins.
    pub line_start: u32,
    /// 1-indexed estimated line where the declaration ends.
    /// For the last symbol this is the total line count; for
    /// others it is the line before the next declaration starts.
    pub line_end: u32,
}

/// Produce a structural outline of `source` for the given `language`.
///
/// Returns an empty `Vec` for languages that have no symbol patterns
/// (e.g. JSON, Markdown). No file I/O; `source` is borrowed text.
pub fn outline_source(source: &str, language: Language) -> Vec<OutlineEntry> {
    let symbols: Vec<Symbol> = extract_symbols(source, language);
    if symbols.is_empty() {
        return Vec::new();
    }

    let total_lines = (source.lines().count() as u32).max(1);
    let n = symbols.len();

    // Two-pass: collect all start lines first so we can compute end
    // lines without needing to re-borrow after move.
    let line_ends: Vec<u32> = (0..n)
        .map(|i| {
            if i + 1 < n {
                // End one line before the next symbol starts.
                // If the next symbol starts on the same line
                // (minified / pathological) use line_start itself.
                let next = symbols[i + 1].line;
                if next > symbols[i].line {
                    next - 1
                } else {
                    symbols[i].line
                }
            } else {
                total_lines
            }
        })
        .collect();

    symbols
        .into_iter()
        .zip(line_ends)
        .map(|(sym, line_end)| OutlineEntry {
            name: sym.name,
            kind: sym.kind,
            line_start: sym.line,
            line_end,
        })
        .collect()
}

/// Produce a structural outline of the file at `path`.
///
/// Reads the file, infers the language from the extension, and calls
/// [`outline_source`]. Returns an empty `Vec` if the file cannot be
/// read or the language has no symbol patterns.
pub fn outline_file(path: &std::path::Path) -> Vec<OutlineEntry> {
    let source = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    outline_source(&source, Language::from_path(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── basic correctness ─────────────────────────────────────────────────

    #[test]
    fn outline_returns_empty_for_unsupported_language() {
        assert!(outline_source("anything here", Language::Markdown).is_empty());
        assert!(outline_source("{ \"key\": 1 }", Language::Json).is_empty());
    }

    #[test]
    fn outline_rust_single_fn() {
        let src = "fn hello() {\n    println!(\"hi\");\n}\n";
        let out = outline_source(src, Language::Rust);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "hello");
        assert_eq!(out[0].kind, SymbolKind::Function);
        assert_eq!(out[0].line_start, 1);
        assert_eq!(out[0].line_end, 3); // last symbol → total lines
    }

    #[test]
    fn outline_rust_multiple_symbols_have_correct_line_ranges() {
        // 4 declarations, each on its own consecutive line.
        let src = "\
pub struct Cfg {}\n\
pub enum Mode { A, B }\n\
pub trait Handler {}\n\
pub fn run() {}\n\
";
        let out = outline_source(src, Language::Rust);
        assert_eq!(out.len(), 4, "got: {out:?}");

        assert_eq!(out[0].name, "Cfg");
        assert_eq!(out[0].line_start, 1);
        assert_eq!(out[0].line_end, 1); // next starts at 2 → end = 1

        assert_eq!(out[1].name, "Mode");
        assert_eq!(out[1].line_start, 2);
        assert_eq!(out[1].line_end, 2);

        assert_eq!(out[2].name, "Handler");
        assert_eq!(out[2].line_start, 3);
        assert_eq!(out[2].line_end, 3);

        assert_eq!(out[3].name, "run");
        assert_eq!(out[3].line_start, 4);
        assert_eq!(out[3].line_end, 4); // last → total = 4
    }

    #[test]
    fn outline_last_symbol_end_line_equals_total_line_count() {
        // fn b spans lines 2-4; total = 4.
        let src = "fn a() {}\nfn b() {\n    // body\n}\n";
        let out = outline_source(src, Language::Rust);
        assert_eq!(out.len(), 2);
        let b = out.iter().find(|e| e.name == "b").unwrap();
        assert_eq!(b.line_end, 4, "last symbol line_end must == total lines");
    }

    #[test]
    fn outline_symbol_kinds_preserved() {
        let src = "\
struct S {}\n\
enum E {}\n\
trait T {}\n\
fn f() {}\n\
mod m {}\n\
type A = u8;\n\
";
        let out = outline_source(src, Language::Rust);
        let kind_of = |name: &str| {
            out.iter()
                .find(|e| e.name == name)
                .map(|e| e.kind)
                .unwrap_or_else(|| panic!("{name} missing"))
        };
        assert_eq!(kind_of("S"), SymbolKind::Struct);
        assert_eq!(kind_of("E"), SymbolKind::Enum);
        assert_eq!(kind_of("T"), SymbolKind::Trait);
        assert_eq!(kind_of("f"), SymbolKind::Function);
        assert_eq!(kind_of("m"), SymbolKind::Module);
        assert_eq!(kind_of("A"), SymbolKind::Type);
    }

    #[test]
    fn outline_python_fn_and_class() {
        // 5 lines; class at 1, method at 2, bar at 4.
        let src = "class Foo:\n    def method(self):\n        pass\n\ndef bar():\n    pass\n";
        let out = outline_source(src, Language::Python);
        assert!(!out.is_empty());
        let foo = out.iter().find(|e| e.name == "Foo").unwrap();
        assert_eq!(foo.kind, SymbolKind::Class);
        assert_eq!(foo.line_start, 1);
        let bar = out.iter().find(|e| e.name == "bar").unwrap();
        assert_eq!(bar.kind, SymbolKind::Function);
        // bar is the last symbol → line_end == total lines
        assert_eq!(bar.line_end, 6);
    }

    #[test]
    fn outline_empty_source_returns_empty() {
        assert!(outline_source("", Language::Rust).is_empty());
        assert!(outline_source("   \n\n  ", Language::Rust).is_empty());
    }

    #[test]
    fn outline_serialises_to_json_with_expected_keys() {
        let src = "pub fn check() -> bool { false }\n";
        let out = outline_source(src, Language::Rust);
        let json = serde_json::to_value(&out).unwrap();
        let entry = &json[0];
        assert!(entry.get("name").is_some(), "name key missing");
        assert!(entry.get("kind").is_some(), "kind key missing");
        assert!(entry.get("line_start").is_some(), "line_start key missing");
        assert!(entry.get("line_end").is_some(), "line_end key missing");
        assert_eq!(entry["name"], "check");
        assert_eq!(entry["kind"], "function");
    }

    // ── outline_file ──────────────────────────────────────────────────────

    #[test]
    fn outline_file_on_real_rust_file() {
        // Point at this module's own source file.
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let this_file = manifest.join("src").join("code_map").join("outline.rs");
        if !this_file.exists() {
            return; // alternate layout — skip
        }
        let out = outline_file(&this_file);
        assert!(
            !out.is_empty(),
            "outline_file returned empty on real .rs file"
        );
        let names: Vec<&str> = out.iter().map(|e| e.name.as_str()).collect();
        // This file defines `outline_source` and `outline_file` at
        // top level — both must appear.
        assert!(
            names.contains(&"outline_source"),
            "outline_source missing from: {names:?}",
        );
        assert!(
            names.contains(&"outline_file"),
            "outline_file missing from: {names:?}",
        );
    }

    #[test]
    fn outline_file_nonexistent_returns_empty() {
        let path = std::path::Path::new("/this/does/not/exist.rs");
        assert!(outline_file(path).is_empty());
    }

    // ── gap guard ─────────────────────────────────────────────────────────

    #[test]
    fn line_end_never_less_than_line_start() {
        // Adjacent single-line declarations.
        let src = "fn a() {}\nfn b() {}\n";
        let out = outline_source(src, Language::Rust);
        for e in &out {
            assert!(
                e.line_end >= e.line_start,
                "line_end < line_start for {}: {} < {}",
                e.name,
                e.line_end,
                e.line_start,
            );
        }
    }
}
