//! K-Repo-Map Phase 2 (Session 14 Pick #16) — symbol extraction.
//!
//! Per-language regex patterns extract top-level declarations
//! (functions / classes / methods / traits / interfaces) from the
//! source text of each `RepoFile`. The result feeds the recall path
//! in Phase 3 so the agent gets "operator's repo defines symbol X
//! at file Y:Z" as part of its context block, without having to
//! grep on every prompt.
//!
//! ## Why regex, not tree-sitter
//!
//! Tree-sitter grammars are C-compiled per language (rust-bindgen
//! variants for each grammar), adding ~30 transitive deps + ~2-5min
//! to the cold build on Windows MSVC. NEOTH's solo-operator daemon
//! is Windows-first; that build-time cost is real. Regex captures
//! ~85% of the symbols a tree-sitter parser would find for the
//! Phase-2 use case (operator wants "where is fn auth_middleware
//! defined?") — the missing 15% (method receivers, nested impls,
//! complex generics) are Phase-2b follow-ups when tree-sitter
//! becomes worth the build cost.
//!
//! ## Patterns by language
//!
//! - **Rust**: `fn name`, `struct Name`, `enum Name`, `trait Name`,
//!   `impl Name`, `mod name`
//! - **Python**: `def name`, `async def name`, `class Name`
//! - **TypeScript / JavaScript**: `function name`, `class Name`,
//!   `interface Name` (TS only), `type Name = ` (TS only),
//!   `export function name`, arrow assignments `const name = `
//! - **Go**: `func Name`, `func (recv) Method`, `type Name`
//! - **Java / Kotlin / Swift / C#**: `class Name`, `interface Name`
//! - **C / C++**: header `function_name(...)`, `struct Name`,
//!   `class Name`
//!
//! Patterns are anchored at line start with optional leading whitespace, so
//! extraction remains intentionally declaration-oriented. Rust functions that
//! matched this scan receive a separate single-pass AST extent certification;
//! declarations the AST cannot prove retain an unknown extent.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use proc_macro2::Span;
use regex::Regex;
use serde::{Deserialize, Serialize};
use syn::visit::Visit;

use super::walker::{DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_SYMBOLS, Language};

/// A single-file extraction cannot retain more declarations than the native
/// map builder retains in total. Callers beyond this cap receive only the
/// bounded prefix; unmapped diff hunks conservatively become file seeds.
const MAX_SYMBOLS_PER_FILE: usize = DEFAULT_MAX_SYMBOLS;
/// Match the native per-file source cap before invoking the Rust AST parser.
const MAX_RUST_AST_SOURCE_BYTES: usize = DEFAULT_MAX_FILE_BYTES as usize;

/// Kind of declaration the regex matched. Coarse enough that it's
/// comparable across languages; refines into language-specific kinds
/// only when Phase 2b promotes to a real AST parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    Function,
    Method,
    Class,
    Struct,
    Enum,
    Trait,
    Interface,
    Module,
    Type,
}

impl SymbolKind {
    pub fn label(self) -> &'static str {
        match self {
            SymbolKind::Function => "function",
            SymbolKind::Method => "method",
            SymbolKind::Class => "class",
            SymbolKind::Struct => "struct",
            SymbolKind::Enum => "enum",
            SymbolKind::Trait => "trait",
            SymbolKind::Interface => "interface",
            SymbolKind::Module => "module",
            SymbolKind::Type => "type",
        }
    }
}

/// One extracted symbol. Path is supplied by the caller (the
/// extractor only sees text + language) so the same struct shape
/// works for in-memory tests + real walker output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Symbol {
    /// Bare identifier name (no module path, no generic parameters).
    pub name: String,
    pub kind: SymbolKind,
    /// 1-indexed line number where the declaration starts.
    pub line: u32,
    /// Inclusive end line of a parser-certified balanced brace body. `None`
    /// means the Rust parser could not prove an extent; consumers must
    /// use a file-level fallback instead of estimating one from declarations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_end: Option<u32>,
}

/// Returns true only for the intentionally small Rust/Python test subset that
/// has both a conventional test-file location and a framework marker. This is
/// evidence classification, not test discovery: helpers, fixtures, generated
/// files and unsupported languages remain unknown to callers.
#[cfg(test)]
pub(crate) fn is_supported_test_declaration(path: &str, source: &str, symbol: &Symbol) -> bool {
    supported_test_declarations(path, source).contains(&(symbol.name.clone(), symbol.line))
}

/// Parse a source file once and return only declarations whose test framework
/// marker is structurally attached to that declaration. Graph construction
/// calls this once per file; the compatibility predicate above is for focused
/// unit callers only.
pub(crate) fn supported_test_declarations(path: &str, source: &str) -> BTreeSet<(String, u32)> {
    let normalized = path.replace('\\', "/");
    if normalized.contains("/fixtures/")
        || normalized.contains("/generated/")
        || normalized.contains("/helpers/")
    {
        return BTreeSet::new();
    }
    if normalized.ends_with(".rs") {
        let conventional = normalized.starts_with("tests/")
            || normalized.contains("/tests/")
            || normalized.ends_with("_test.rs");
        return if conventional {
            rust_framework_tests(source)
        } else {
            BTreeSet::new()
        };
    }
    if normalized.ends_with(".py") {
        let filename = normalized.rsplit('/').next().unwrap_or_default();
        let conventional = normalized.starts_with("tests/")
            || normalized.contains("/tests/")
            || (filename.starts_with("test_") && filename.ends_with(".py"))
            || filename.ends_with("_test.py");
        return if conventional {
            python_framework_tests(source)
        } else {
            BTreeSet::new()
        };
    }
    BTreeSet::new()
}

fn rust_framework_tests(source: &str) -> BTreeSet<(String, u32)> {
    let Ok(file) = syn::parse_file(source) else {
        return BTreeSet::new();
    };
    let mut collector = RustTestDeclarations::default();
    collector.visit_file(&file);
    collector.declarations
}

#[derive(Default)]
struct RustTestDeclarations {
    declarations: BTreeSet<(String, u32)>,
}

impl RustTestDeclarations {
    fn record(&mut self, attrs: &[syn::Attribute], ident: &syn::Ident, fn_span: Span) {
        if attrs.iter().any(|attr| attr.path().is_ident("test"))
            && let Ok(line) = u32::try_from(fn_span.start().line)
        {
            self.declarations.insert((ident.to_string(), line));
        }
    }
}

impl<'ast> Visit<'ast> for RustTestDeclarations {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.record(&item.attrs, &item.sig.ident, item.sig.fn_token.span);
        syn::visit::visit_item_fn(self, item);
    }
    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        self.record(&item.attrs, &item.sig.ident, item.sig.fn_token.span);
        syn::visit::visit_impl_item_fn(self, item);
    }
}

fn python_framework_tests(source: &str) -> BTreeSet<(String, u32)> {
    let stripped = super::graph::strip_comments_and_strings_hash_family(source);
    let mut tests = BTreeSet::new();
    let mut scopes: Vec<PythonScope> = Vec::new();
    let mut decorators: Vec<(usize, String)> = Vec::new();
    for (index, raw) in stripped.lines().enumerate() {
        let indent = raw.len() - raw.trim_start().len();
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        while scopes.last().is_some_and(|scope| indent <= scope.indent()) {
            scopes.pop();
        }
        if line.starts_with('@') {
            decorators.push((indent, line.to_owned()));
            continue;
        }
        if let Some(name) = python_class_name(line) {
            let testcase = line.contains("unittest.TestCase");
            scopes.push(PythonScope::Class { indent, testcase });
            decorators.clear();
            let _ = name;
            continue;
        }
        if let Some(name) = python_def_name(line) {
            let pytest = decorators.iter().any(|(decorator_indent, decorator)| {
                *decorator_indent == indent && decorator.starts_with("@pytest.mark.")
            });
            let top_level_pytest = pytest && scopes.is_empty() && indent == 0;
            let direct_unittest_method = matches!(
                scopes.last(),
                Some(PythonScope::Class { testcase: true, .. })
            );
            if name.starts_with("test_") && (top_level_pytest || direct_unittest_method) {
                tests.insert((name.to_owned(), (index + 1) as u32));
            }
            scopes.push(PythonScope::Function { indent });
            decorators.clear();
            continue;
        }
        decorators.clear();
    }
    tests
}

enum PythonScope {
    Class { indent: usize, testcase: bool },
    Function { indent: usize },
}

impl PythonScope {
    fn indent(&self) -> usize {
        match self {
            Self::Class { indent, .. } | Self::Function { indent } => *indent,
        }
    }
}

fn python_def_name(line: &str) -> Option<&str> {
    let line = line.strip_prefix("async ").unwrap_or(line);
    let rest = line.strip_prefix("def ")?;
    let end = rest.find('(')?;
    Some(&rest[..end])
}

fn python_class_name(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("class ")?;
    let end = rest.find('(').or_else(|| rest.find(':'))?;
    Some(&rest[..end])
}

/// A possible TestedBy target must be a supported-language declaration in a
/// production source location. The inverse of test classification is not
/// sufficient: helpers, fixtures and generated sources intentionally remain
/// non-production/unknown rather than becoming exact evidence.
pub(crate) fn is_supported_production_declaration(path: &str, symbol: &Symbol) -> bool {
    let normalized = path.replace('\\', "/");
    let excluded = normalized.starts_with("tests/")
        || normalized.contains("/tests/")
        || normalized.contains("/fixtures/")
        || normalized.contains("/generated/")
        || normalized.contains("/helpers/")
        || normalized.ends_with("_test.rs")
        || normalized.ends_with("_test.py");
    !excluded
        && matches!(symbol.kind, SymbolKind::Function | SymbolKind::Method)
        && (normalized.ends_with(".rs") || normalized.ends_with(".py"))
}

/// Public entry — given source text + language, return all
/// declarations the regex patterns can identify. Order matches the
/// source-file scan order.
pub fn extract_symbols(text: &str, language: Language) -> Vec<Symbol> {
    let patterns = patterns_for(language);
    if patterns.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (line_idx, line) in text.lines().enumerate() {
        for (kind, re) in patterns {
            if let Some(captures) = re.captures(line) {
                // The pattern always exposes the symbol name as
                // capture group 1.
                if let Some(name_match) = captures.get(1) {
                    let name = name_match.as_str().to_string();
                    if out.len() == MAX_SYMBOLS_PER_FILE {
                        return out;
                    }
                    out.push(Symbol {
                        name,
                        kind: *kind,
                        line: (line_idx as u32) + 1,
                        line_end: None,
                    });
                    // Once a line matches one pattern don't try the
                    // others — prevents `fn foo(x: SomeStruct)` from
                    // also matching the struct pattern on the same
                    // line.
                    break;
                }
            }
        }
    }
    if language == Language::Rust {
        apply_rust_function_extents(text, &mut out);
    }
    out
}

/// Populate inclusive function extents from one complete Rust AST parse.
///
/// Syn owns Rust's lexical and delimiter rules, so raw strings, lifetimes,
/// destructuring parameters, const generics, and multiline return types cannot
/// be mistaken for a function body. A parse error leaves all extents unknown:
/// downstream diff mapping then produces a file seed instead of a guessed
/// declaration seed.
fn apply_rust_function_extents(text: &str, symbols: &mut [Symbol]) {
    if text.len() > MAX_RUST_AST_SOURCE_BYTES {
        return;
    }
    let Ok(file) = syn::parse_file(text) else {
        return;
    };
    let mut collector = RustFunctionExtents::default();
    collector.visit_file(&file);
    for symbol in symbols
        .iter_mut()
        .filter(|symbol| symbol.kind == SymbolKind::Function)
    {
        symbol.line_end = collector
            .extents
            .get(&(symbol.name.clone(), symbol.line))
            .copied();
    }
}

#[derive(Default)]
struct RustFunctionExtents {
    extents: BTreeMap<(String, u32), u32>,
}

impl RustFunctionExtents {
    fn record(&mut self, ident: &syn::Ident, function_span: Span, close_span: Span) {
        let start = function_span.start().line;
        let end = close_span.end().line;
        if let (Ok(start), Ok(end)) = (u32::try_from(start), u32::try_from(end))
            && end >= start
        {
            self.extents.insert((ident.to_string(), start), end);
        }
    }
}

impl<'ast> Visit<'ast> for RustFunctionExtents {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        // Regex extraction records the physical function-keyword line, which
        // can differ from an outer attribute's span start.
        self.record(
            &item.sig.ident,
            item.sig.fn_token.span,
            item.block.brace_token.span.close(),
        );
        syn::visit::visit_item_fn(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        self.record(
            &item.sig.ident,
            item.sig.fn_token.span,
            item.block.brace_token.span.close(),
        );
        syn::visit::visit_impl_item_fn(self, item);
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if let Some(body) = &item.default {
            self.record(
                &item.sig.ident,
                item.sig.fn_token.span,
                body.brace_token.span.close(),
            );
        }
        syn::visit::visit_trait_item_fn(self, item);
    }
}

/// Compiled regex registry per language. Lazy-initialised because
/// regex compilation is non-trivial; warm-cached for the whole
/// process lifetime.
fn patterns_for(language: Language) -> &'static [(SymbolKind, Regex)] {
    match language {
        Language::Rust => rust_patterns(),
        Language::Python => python_patterns(),
        Language::TypeScript | Language::JavaScript => ts_js_patterns(),
        Language::Go => go_patterns(),
        Language::Java | Language::Kotlin | Language::Swift | Language::CSharp => {
            jvm_like_patterns()
        }
        Language::C | Language::Cpp => c_cpp_patterns(),
        _ => &[],
    }
}

fn rust_patterns() -> &'static [(SymbolKind, Regex)] {
    static CELL: OnceLock<Vec<(SymbolKind, Regex)>> = OnceLock::new();
    CELL.get_or_init(|| {
        vec![
            (
                SymbolKind::Function,
                Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:const\s+)?(?:unsafe\s+)?(?:extern(?:\s+\x22[^\x22]*\x22)?\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)")
                    .unwrap(),
            ),
            (
                SymbolKind::Struct,
                Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)")
                    .unwrap(),
            ),
            (
                SymbolKind::Enum,
                Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?enum\s+([A-Za-z_][A-Za-z0-9_]*)")
                    .unwrap(),
            ),
            (
                SymbolKind::Trait,
                Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?trait\s+([A-Za-z_][A-Za-z0-9_]*)")
                    .unwrap(),
            ),
            (
                SymbolKind::Module,
                Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)")
                    .unwrap(),
            ),
            (
                SymbolKind::Type,
                Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?type\s+([A-Za-z_][A-Za-z0-9_]*)")
                    .unwrap(),
            ),
        ]
    }).as_slice()
}

fn python_patterns() -> &'static [(SymbolKind, Regex)] {
    static CELL: OnceLock<Vec<(SymbolKind, Regex)>> = OnceLock::new();
    CELL.get_or_init(|| {
        vec![
            (
                SymbolKind::Function,
                Regex::new(r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap(),
            ),
            (
                SymbolKind::Class,
                Regex::new(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap(),
            ),
        ]
    })
    .as_slice()
}

fn ts_js_patterns() -> &'static [(SymbolKind, Regex)] {
    static CELL: OnceLock<Vec<(SymbolKind, Regex)>> = OnceLock::new();
    CELL.get_or_init(|| {
        vec![
            (
                SymbolKind::Function,
                Regex::new(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][A-Za-z0-9_$]*)")
                    .unwrap(),
            ),
            (
                SymbolKind::Class,
                Regex::new(r"^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][A-Za-z0-9_$]*)")
                    .unwrap(),
            ),
            (
                SymbolKind::Interface,
                Regex::new(r"^\s*(?:export\s+)?interface\s+([A-Za-z_$][A-Za-z0-9_$]*)")
                    .unwrap(),
            ),
            (
                SymbolKind::Type,
                Regex::new(r"^\s*(?:export\s+)?type\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=")
                    .unwrap(),
            ),
            (
                SymbolKind::Function,
                Regex::new(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*[:=]\s*(?:async\s+)?(?:\([^)]*\)\s*=>|function\b)")
                    .unwrap(),
            ),
        ]
    }).as_slice()
}

fn go_patterns() -> &'static [(SymbolKind, Regex)] {
    static CELL: OnceLock<Vec<(SymbolKind, Regex)>> = OnceLock::new();
    CELL.get_or_init(|| {
        vec![
            (
                SymbolKind::Method,
                Regex::new(r"^\s*func\s+\([^)]+\)\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap(),
            ),
            (
                SymbolKind::Function,
                Regex::new(r"^\s*func\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap(),
            ),
            (
                SymbolKind::Type,
                Regex::new(r"^\s*type\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap(),
            ),
        ]
    })
    .as_slice()
}

fn jvm_like_patterns() -> &'static [(SymbolKind, Regex)] {
    static CELL: OnceLock<Vec<(SymbolKind, Regex)>> = OnceLock::new();
    CELL.get_or_init(|| {
        vec![
            (
                SymbolKind::Class,
                Regex::new(r"^\s*(?:public\s+|private\s+|protected\s+|internal\s+|abstract\s+|final\s+|sealed\s+|data\s+|open\s+|static\s+)*class\s+([A-Za-z_][A-Za-z0-9_]*)")
                    .unwrap(),
            ),
            (
                SymbolKind::Interface,
                Regex::new(r"^\s*(?:public\s+|private\s+|protected\s+|internal\s+)*interface\s+([A-Za-z_][A-Za-z0-9_]*)")
                    .unwrap(),
            ),
        ]
    }).as_slice()
}

fn c_cpp_patterns() -> &'static [(SymbolKind, Regex)] {
    static CELL: OnceLock<Vec<(SymbolKind, Regex)>> = OnceLock::new();
    CELL.get_or_init(|| {
        vec![
            (
                SymbolKind::Struct,
                Regex::new(r"^\s*(?:typedef\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap(),
            ),
            (
                SymbolKind::Class,
                Regex::new(r"^\s*(?:template\s*<[^>]*>\s*)?class\s+([A-Za-z_][A-Za-z0-9_]*)")
                    .unwrap(),
            ),
        ]
    })
    .as_slice()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_function_pub_async_const() {
        let text = "pub async fn handle_request() { }\n";
        let s = extract_symbols(text, Language::Rust);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].name, "handle_request");
        assert_eq!(s[0].kind, SymbolKind::Function);
        assert_eq!(s[0].line, 1);
    }

    #[test]
    fn rust_function_with_visibility_qualifier() {
        let text = "pub(crate) fn internal_helper() {}\npub(super) fn parent_visible() {}\n";
        let s = extract_symbols(text, Language::Rust);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].name, "internal_helper");
        assert_eq!(s[1].name, "parent_visible");
    }

    #[test]
    fn rust_struct_enum_trait_module_type() {
        let text = "
pub struct Foo {}
enum Bar {}
trait Baz {}
mod inner {}
type Alias = u64;
";
        let s = extract_symbols(text, Language::Rust);
        let names: Vec<&str> = s.iter().map(|x| x.name.as_str()).collect();
        assert!(names.contains(&"Foo"));
        assert!(names.contains(&"Bar"));
        assert!(names.contains(&"Baz"));
        assert!(names.contains(&"inner"));
        assert!(names.contains(&"Alias"));
    }

    #[test]
    fn rust_one_line_one_symbol_no_struct_misdetection() {
        // `fn foo(x: SomeStruct)` must NOT also match the struct
        // pattern — the loop-break invariant prevents double-tag.
        let text = "fn process(arg: MyStruct) {}\n";
        let s = extract_symbols(text, Language::Rust);
        assert_eq!(s.len(), 1, "expected one symbol, got: {s:?}");
        assert_eq!(s[0].kind, SymbolKind::Function);
    }

    #[test]
    fn python_def_class_async() {
        let text = "
def regular():
    pass

async def asynchronous():
    pass

class Foo:
    def method(self):
        pass
";
        let s = extract_symbols(text, Language::Python);
        let names: Vec<&str> = s.iter().map(|x| x.name.as_str()).collect();
        assert!(names.contains(&"regular"));
        assert!(names.contains(&"asynchronous"));
        assert!(names.contains(&"Foo"));
        assert!(names.contains(&"method"));
    }

    #[test]
    fn typescript_function_class_interface_type() {
        let text = "
export function namedFn() {}
export default async function defaultFn() {}
class MyClass {}
interface MyIface {}
type MyType = string;
export const arrow = async () => {};
";
        let s = extract_symbols(text, Language::TypeScript);
        let names: Vec<&str> = s.iter().map(|x| x.name.as_str()).collect();
        assert!(names.contains(&"namedFn"));
        assert!(names.contains(&"defaultFn"));
        assert!(names.contains(&"MyClass"));
        assert!(names.contains(&"MyIface"));
        assert!(names.contains(&"MyType"));
        assert!(names.contains(&"arrow"));
    }

    #[test]
    fn go_func_method_type() {
        let text = "
func TopLevel() {}
func (r *Receiver) Method() {}
type Person struct {}
";
        let s = extract_symbols(text, Language::Go);
        let names: Vec<&str> = s.iter().map(|x| x.name.as_str()).collect();
        assert!(names.contains(&"TopLevel"));
        assert!(names.contains(&"Method"));
        assert!(names.contains(&"Person"));
    }

    #[test]
    fn java_class_interface() {
        let text = "
public class UserService {}
interface Repository {}
private static class Inner {}
";
        let s = extract_symbols(text, Language::Java);
        let names: Vec<&str> = s.iter().map(|x| x.name.as_str()).collect();
        assert!(names.contains(&"UserService"));
        assert!(names.contains(&"Repository"));
        assert!(names.contains(&"Inner"));
    }

    #[test]
    fn cpp_class_struct() {
        let text = "
class Widget {};
struct Point { int x; int y; };
";
        let s = extract_symbols(text, Language::Cpp);
        let names: Vec<&str> = s.iter().map(|x| x.name.as_str()).collect();
        assert!(names.contains(&"Widget"));
        assert!(names.contains(&"Point"));
    }

    #[test]
    fn line_numbers_are_one_indexed() {
        let text = "line1\nfn foo() {}\nline3\n";
        let s = extract_symbols(text, Language::Rust);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].line, 2);
    }

    #[test]
    fn rust_balanced_extents_cover_multiline_and_nested_function_bodies() {
        let source = concat!(
            "fn outer(\n",
            "    input: u32,\n",
            ") -> u32 {\n",
            "    fn inner() {\n",
            "        if input > 0 { println!(\"{not a brace}\"); }\n",
            "    }\n",
            "    inner();\n",
            "    input\n",
            "}\n",
        );
        let symbols = extract_symbols(source, Language::Rust);
        let outer = symbols
            .iter()
            .find(|symbol| symbol.name == "outer")
            .unwrap();
        let inner = symbols
            .iter()
            .find(|symbol| symbol.name == "inner")
            .unwrap();
        assert_eq!(outer.line, 1);
        assert_eq!(outer.line_end, Some(9));
        assert_eq!(inner.line, 4);
        assert_eq!(inner.line_end, Some(6));
    }

    #[test]
    fn rust_extent_stays_unknown_for_unbalanced_or_semicolon_declarations() {
        let trait_method = extract_symbols("fn declaration_only();\n", Language::Rust);
        assert_eq!(trait_method[0].line_end, None);
        let unbalanced = extract_symbols("fn broken() {\n", Language::Rust);
        assert_eq!(unbalanced[0].line_end, None);
    }

    #[test]
    fn rust_ast_extents_cover_raw_strings_lifetimes_and_complex_headers() {
        let raw = extract_symbols(
            r##"fn raw() { let text = r#" quote " } hidden "#; }"##,
            Language::Rust,
        );
        assert_eq!(raw[0].line_end, Some(1));
        let lifetime = extract_symbols(
            "fn borrow<'a>(value: &'a str) { drop(value); }\n",
            Language::Rust,
        );
        assert_eq!(lifetime[0].line_end, Some(1));
        let return_type_const =
            extract_symbols("fn array() -> [u8; { 1 + 1 }] { [0; 2] }\n", Language::Rust);
        assert_eq!(return_type_const[0].line_end, Some(1));
        let destructured = extract_symbols(
            "fn take(Foo { value }: Foo) { drop(value); }\n",
            Language::Rust,
        );
        assert_eq!(destructured[0].line_end, Some(1));
        let multiline_const = extract_symbols(
            "fn generic<\n    const N: usize = { 1 + 1 },\n>() {\n    let _ = N;\n}\n",
            Language::Rust,
        );
        assert_eq!(multiline_const[0].line_end, Some(5));
    }

    #[test]
    fn rust_ast_extent_uses_function_keyword_line_after_outer_attributes() {
        let symbols = extract_symbols(
            "#[inline]\nfn attributed() {\n    body();\n}\n",
            Language::Rust,
        );
        assert_eq!(symbols[0].line, 2);
        assert_eq!(symbols[0].line_end, Some(4));
    }

    #[test]
    fn rust_ast_extents_cover_impl_and_trait_default_methods_only() {
        let symbols = extract_symbols(
            concat!(
                "impl Widget {\n",
                "    fn method(&self) {\n",
                "        work();\n",
                "    }\n",
                "}\n",
                "trait Behavior {\n",
                "    fn required(&self);\n",
                "    fn defaulted(&self) {\n",
                "        work();\n",
                "    }\n",
                "}\n",
            ),
            Language::Rust,
        );
        assert_eq!(
            symbols
                .iter()
                .find(|symbol| symbol.name == "method")
                .unwrap()
                .line_end,
            Some(4)
        );
        assert_eq!(
            symbols
                .iter()
                .find(|symbol| symbol.name == "required")
                .unwrap()
                .line_end,
            None
        );
        assert_eq!(
            symbols
                .iter()
                .find(|symbol| symbol.name == "defaulted")
                .unwrap()
                .line_end,
            Some(10)
        );
    }

    #[test]
    fn malformed_rust_leaves_every_function_extent_unknown() {
        let symbols = extract_symbols("fn valid() {}\nfn broken( {\n", Language::Rust);
        assert_eq!(symbols[0].line_end, None);
        assert_eq!(symbols[1].line_end, None);
    }

    #[test]
    fn unsupported_language_returns_empty() {
        let s = extract_symbols("fn foo() {}", Language::Markdown);
        assert!(s.is_empty());
        let s = extract_symbols("anything", Language::Other);
        assert!(s.is_empty());
    }

    #[test]
    fn indented_declarations_still_match() {
        // Nested-impl method-style definitions inside `impl` blocks.
        let text = "
impl Foo {
    pub fn method_inside_impl(&self) -> u32 { 0 }
}
";
        let s = extract_symbols(text, Language::Rust);
        let names: Vec<&str> = s.iter().map(|x| x.name.as_str()).collect();
        assert!(names.contains(&"method_inside_impl"));
    }

    #[test]
    fn symbol_kind_serialises_snake_case() {
        let s = serde_json::to_value(SymbolKind::Function).unwrap();
        assert_eq!(s.as_str().unwrap(), "function");
        let s = serde_json::to_value(SymbolKind::Class).unwrap();
        assert_eq!(s.as_str().unwrap(), "class");
    }

    #[test]
    fn symbol_kind_labels_match_serde() {
        for kind in [
            SymbolKind::Function,
            SymbolKind::Method,
            SymbolKind::Class,
            SymbolKind::Struct,
            SymbolKind::Enum,
            SymbolKind::Trait,
            SymbolKind::Interface,
            SymbolKind::Module,
            SymbolKind::Type,
        ] {
            let json = serde_json::to_value(kind).unwrap();
            assert_eq!(json.as_str().unwrap(), kind.label());
        }
    }

    #[test]
    fn empty_text_returns_empty() {
        assert!(extract_symbols("", Language::Rust).is_empty());
        assert!(extract_symbols("   \n\n   ", Language::Rust).is_empty());
    }

    #[test]
    fn pattern_recompilation_is_cached() {
        // Drift guard: calling extract twice must not recompile. We
        // can't directly observe that, but we can confirm the
        // returned static-slice lifetime is stable across calls.
        let p1 = patterns_for(Language::Rust).as_ptr();
        let p2 = patterns_for(Language::Rust).as_ptr();
        assert_eq!(p1, p2, "patterns_for should return cached slice");
    }

    #[test]
    fn test_classification_requires_conventional_path_and_framework_marker() {
        let rust = extract_symbols("#[test]\nfn verifies() {}\n", Language::Rust);
        assert!(is_supported_test_declaration(
            "tests/unit_test.rs",
            "#[test]\nfn verifies() {}\n",
            &rust[0]
        ));
        assert!(!is_supported_test_declaration(
            "src/helper.rs",
            "#[test]\nfn verifies() {}\n",
            &rust[0]
        ));
        assert!(!is_supported_test_declaration(
            "tests/fixtures/unit_test.rs",
            "#[test]\nfn verifies() {}\n",
            &rust[0]
        ));
        let python = extract_symbols("@pytest.mark.unit\ndef test_ok(): pass\n", Language::Python);
        assert!(is_supported_test_declaration(
            "tests/test_ok.py",
            "@pytest.mark.unit\ndef test_ok(): pass\n",
            &python[0]
        ));
    }

    #[test]
    fn test_markers_in_comments_and_strings_are_not_evidence() {
        let rust_source = "// #[test]\nfn looks_like_test() {}\n";
        let rust = extract_symbols(rust_source, Language::Rust);
        assert!(!is_supported_test_declaration(
            "tests/looks_test.rs",
            rust_source,
            &rust[0]
        ));
        let python_source = "# @pytest.mark.unit\ndef test_comment_only(): pass\n";
        let python = extract_symbols(python_source, Language::Python);
        assert!(!is_supported_test_declaration(
            "tests/test_comment.py",
            python_source,
            &python[0]
        ));
    }

    #[test]
    fn pytest_decorator_and_unittest_class_are_supported_code_markers() {
        let pytest_source = "@pytest.mark.unit\ndef test_pytest(): pass\n";
        let pytest = extract_symbols(pytest_source, Language::Python);
        assert!(is_supported_test_declaration(
            "tests/test_pytest.py",
            pytest_source,
            &pytest[0]
        ));
        let unittest_source =
            "class Cases(unittest.TestCase):\n    def test_unittest(self): pass\n";
        let unittest = extract_symbols(unittest_source, Language::Python);
        let test = unittest
            .iter()
            .find(|symbol| symbol.name == "test_unittest")
            .unwrap();
        assert!(is_supported_test_declaration(
            "tests/test_unittest.py",
            unittest_source,
            test
        ));
    }

    #[test]
    fn framework_markers_bind_only_to_their_own_declaration() {
        let rust_source = "#[test]\nfn earlier() {}\nfn later() {}\n";
        let rust = extract_symbols(rust_source, Language::Rust);
        assert!(is_supported_test_declaration(
            "tests/case_test.rs",
            rust_source,
            &rust[0]
        ));
        assert!(!is_supported_test_declaration(
            "tests/case_test.rs",
            rust_source,
            &rust[1]
        ));
        let python_source = "@pytest.mark.unit\ndef helper(): pass\ndef test_later(): pass\n";
        let python = extract_symbols(python_source, Language::Python);
        let later = python
            .iter()
            .find(|symbol| symbol.name == "test_later")
            .unwrap();
        assert!(!is_supported_test_declaration(
            "tests/test_case.py",
            python_source,
            later
        ));
    }

    #[test]
    fn unittest_scope_excludes_module_level_function_after_class() {
        let source = "class Cases(unittest.TestCase):\n    def test_inside(self): pass\n\ndef test_outside(): pass\n";
        let symbols = extract_symbols(source, Language::Python);
        let inside = symbols
            .iter()
            .find(|symbol| symbol.name == "test_inside")
            .unwrap();
        let outside = symbols
            .iter()
            .find(|symbol| symbol.name == "test_outside")
            .unwrap();
        assert!(is_supported_test_declaration(
            "tests/test_case.py",
            source,
            inside
        ));
        assert!(!is_supported_test_declaration(
            "tests/test_case.py",
            source,
            outside
        ));
    }

    #[test]
    fn python_supported_tests_are_only_top_level_or_direct_testcase_methods() {
        let source = concat!(
            "class Cases(unittest.TestCase):\n",
            "    def test_direct(self): pass\n",
            "    def helper(self):\n",
            "        def test_nested(self): pass\n",
            "\n",
            "@pytest.mark.unit\n",
            "def test_top_level(): pass\n",
            "def helper_pytest():\n",
            "    @pytest.mark.unit\n",
            "    def test_nested_pytest(): pass\n",
        );
        let symbols = extract_symbols(source, Language::Python);
        for name in ["test_direct", "test_top_level"] {
            let symbol = symbols.iter().find(|symbol| symbol.name == name).unwrap();
            assert!(is_supported_test_declaration(
                "tests/test_scopes.py",
                source,
                symbol
            ));
        }
        for name in ["test_nested", "test_nested_pytest"] {
            let symbol = symbols.iter().find(|symbol| symbol.name == name).unwrap();
            assert!(!is_supported_test_declaration(
                "tests/test_scopes.py",
                source,
                symbol
            ));
        }
    }
}
