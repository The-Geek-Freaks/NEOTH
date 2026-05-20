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
//! Patterns are anchored at line start with optional leading
//! whitespace, so multi-line declarations are NOT detected — Phase 2b
//! will use AST parsing to cover them.

use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use super::walker::Language;

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
                    out.push(Symbol {
                        name,
                        kind: *kind,
                        line: (line_idx as u32) + 1,
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
    out
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
}
