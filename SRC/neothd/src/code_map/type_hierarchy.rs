//! Conservative source-scope-proven type hierarchy.
//!
//! This module stores only direct relationships that syntax proves inside one
//! scanned root-relative source file and lexical declaration scope. External
//! names, aliases, generics, qualified paths and ambiguous declarations remain
//! unknown. Persistence and MCP publication are deliberately separate work.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use syn::visit::Visit;

use super::walker::{DEFAULT_MAX_FILE_BYTES, Language};

pub const DEFAULT_MAX_TYPE_EDGES: usize = 100_000;
pub const DEFAULT_MAX_TYPE_QUERY_DEPTH: usize = 16;
pub const DEFAULT_MAX_TYPE_QUERY_NODES: usize = 10_000;
pub const DEFAULT_MAX_TYPE_QUERY_TEXT_BYTES: usize = 2 * 1024 * 1024;
pub const DEFAULT_MAX_TYPE_QUERY_WORK_STEPS: usize = 100_000;
pub const DEFAULT_MAX_TYPE_SOURCE_BYTES: usize = 32 * 1024 * 1024;
pub const DEFAULT_MAX_TYPE_DECLARATIONS: usize = 250_000;
const MAX_PYTHON_HEADER_LINES: usize = 8;
const MAX_PYTHON_HEADER_BYTES: usize = 1024;

/// Exact root-relative declaration identity. Rust nested modules use a
/// module-qualified symbol; Python support is intentionally top-level only.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TypeEndpoint {
    pub file_path: String,
    pub symbol: String,
}

impl TypeEndpoint {
    pub fn new(file_path: impl Into<String>, symbol: impl Into<String>) -> Result<Self> {
        let endpoint = Self {
            file_path: file_path.into(),
            symbol: symbol.into(),
        };
        validate_endpoint(&endpoint)?;
        Ok(endpoint)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TypeHierarchyEdge {
    /// Concrete type or subtrait.
    pub child: TypeEndpoint,
    /// Direct trait or supertrait.
    pub parent: TypeEndpoint,
    pub language: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeHierarchyDirection {
    #[default]
    Ancestors,
    Descendants,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TypeHierarchyEntry {
    pub endpoint: TypeEndpoint,
    pub depth: usize,
}

/// Every query supplies explicit bounds. An exceeded bound is an error before
/// retaining an over-budget row, never a partial hierarchy claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypeTraversalBudget {
    pub max_depth: usize,
    pub max_nodes: usize,
    pub max_text_bytes: usize,
    pub max_work_steps: usize,
}

impl Default for TypeTraversalBudget {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_TYPE_QUERY_DEPTH,
            max_nodes: DEFAULT_MAX_TYPE_QUERY_NODES,
            max_text_bytes: DEFAULT_MAX_TYPE_QUERY_TEXT_BYTES,
            max_work_steps: DEFAULT_MAX_TYPE_QUERY_WORK_STEPS,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct TypeHierarchy {
    edges: Vec<TypeHierarchyEdge>,
    endpoints: BTreeSet<TypeEndpoint>,
    ancestors: BTreeMap<TypeEndpoint, Vec<TypeEndpoint>>,
    descendants: BTreeMap<TypeEndpoint, Vec<TypeEndpoint>>,
}

impl TypeHierarchy {
    /// Reconstruct one persisted hierarchy without losing declarations that
    /// currently have no direct parent or child edge. Persistence validates
    /// root membership separately; this constructor validates endpoint shape
    /// and relationship invariants before adjacency is materialized.
    pub fn from_parts(
        edges: Vec<TypeHierarchyEdge>,
        endpoints: BTreeSet<TypeEndpoint>,
    ) -> Result<Self> {
        for endpoint in &endpoints {
            validate_endpoint(&endpoint)?;
        }
        for edge in &edges {
            ensure!(
                endpoints.contains(&edge.child) && endpoints.contains(&edge.parent),
                "type hierarchy edge endpoint is absent from the authoritative declaration inventory"
            );
        }
        let mut hierarchy = Self::from_edges(edges)?;
        hierarchy.endpoints = endpoints;
        Ok(hierarchy)
    }

    pub fn from_edges(mut edges: Vec<TypeHierarchyEdge>) -> Result<Self> {
        for edge in &edges {
            validate_endpoint(&edge.child)?;
            validate_endpoint(&edge.parent)?;
            ensure!(
                matches!(edge.language.as_str(), "rust" | "python"),
                "type edge has unsupported language"
            );
            ensure!(
                edge.child != edge.parent,
                "type hierarchy does not store self edges"
            );
        }
        edges.sort();
        edges.dedup();
        let mut graph = Self {
            edges,
            ..Self::default()
        };
        for edge in &graph.edges {
            graph.endpoints.insert(edge.child.clone());
            graph.endpoints.insert(edge.parent.clone());
            graph
                .ancestors
                .entry(edge.child.clone())
                .or_default()
                .push(edge.parent.clone());
            graph
                .descendants
                .entry(edge.parent.clone())
                .or_default()
                .push(edge.child.clone());
        }
        for adjacent in graph
            .ancestors
            .values_mut()
            .chain(graph.descendants.values_mut())
        {
            adjacent.sort();
            adjacent.dedup();
        }
        Ok(graph)
    }

    pub fn edges(&self) -> &[TypeHierarchyEdge] {
        &self.edges
    }

    pub fn endpoints(&self) -> &BTreeSet<TypeEndpoint> {
        &self.endpoints
    }

    /// Sources must be the exact byte/hash-validated corpus for one canonical
    /// root. There is no cross-file bare-name resolution: an edge must be
    /// proven in its own Rust module scope or Python top-level file scope.
    pub fn build_bounded(sources: &[(String, Language, String)], max_edges: usize) -> Result<Self> {
        let mut paths = BTreeSet::new();
        let mut source_bytes = 0usize;
        for (path, _, source) in sources {
            ensure!(
                is_relative_file_path(path),
                "type hierarchy source path must be canonical root-relative"
            );
            ensure!(
                paths.insert(path.clone()),
                "type hierarchy source path is duplicated"
            );
            ensure!(
                source.as_bytes().len() <= DEFAULT_MAX_FILE_BYTES as usize,
                "type hierarchy source exceeds bounded per-file byte cap"
            );
            source_bytes = source_bytes
                .checked_add(source.as_bytes().len())
                .ok_or_else(|| anyhow::anyhow!("type hierarchy source byte counter overflow"))?;
            ensure!(
                source_bytes <= DEFAULT_MAX_TYPE_SOURCE_BYTES,
                "type hierarchy sources exceed bounded total byte cap"
            );
        }
        let mut edges = Vec::new();
        let mut declarations = BTreeSet::new();
        for (file_path, language, source) in sources {
            let (mut found, found_declarations) = match language {
                Language::Rust => rust_edges(file_path, source),
                Language::Python => python_edges(file_path, source),
                _ => (Vec::new(), BTreeSet::new()),
            };
            declarations.extend(found_declarations);
            ensure!(
                declarations.len() <= DEFAULT_MAX_TYPE_DECLARATIONS,
                "type hierarchy exceeds bounded declaration endpoint cap"
            );
            found.sort();
            found.dedup();
            for edge in found {
                if edges.len() >= max_edges {
                    bail!("type hierarchy exceeds bounded {max_edges}-edge publish cap");
                }
                edges.push(edge);
            }
        }
        let mut hierarchy = Self::from_edges(edges)?;
        hierarchy.endpoints.extend(declarations);
        Ok(hierarchy)
    }

    pub fn query_bounded(
        &self,
        endpoint: &TypeEndpoint,
        direction: TypeHierarchyDirection,
        budget: TypeTraversalBudget,
    ) -> Result<Vec<TypeHierarchyEntry>> {
        validate_endpoint(endpoint)?;
        ensure!(
            self.endpoints.contains(endpoint),
            "type hierarchy endpoint is not an exact declaration in this root generation"
        );
        if budget.max_depth == 0 {
            return Ok(Vec::new());
        }
        let adjacency = match direction {
            TypeHierarchyDirection::Ancestors => &self.ancestors,
            TypeHierarchyDirection::Descendants => &self.descendants,
        };
        let mut queue = VecDeque::from([(endpoint.clone(), 0usize)]);
        let mut seen = BTreeSet::from([endpoint.clone()]);
        let mut entries = Vec::new();
        let mut text_bytes = 0usize;
        let mut work_steps = 0usize;
        while let Some((current, depth)) = queue.pop_front() {
            if depth >= budget.max_depth {
                continue;
            }
            for next in adjacency.get(&current).into_iter().flatten() {
                work_steps = work_steps
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("type hierarchy work counter overflow"))?;
                if work_steps > budget.max_work_steps {
                    bail!(
                        "type hierarchy query exceeds bounded {}-step work budget",
                        budget.max_work_steps
                    );
                }
                if !seen.insert(next.clone()) {
                    continue;
                }
                if entries.len() >= budget.max_nodes {
                    bail!(
                        "type hierarchy query exceeds bounded {}-node budget",
                        budget.max_nodes
                    );
                }
                let next_text = next
                    .file_path
                    .len()
                    .checked_add(next.symbol.len())
                    .and_then(|size| text_bytes.checked_add(size))
                    .ok_or_else(|| anyhow::anyhow!("type hierarchy text counter overflow"))?;
                if next_text > budget.max_text_bytes {
                    bail!(
                        "type hierarchy query exceeds bounded {}-byte text budget",
                        budget.max_text_bytes
                    );
                }
                text_bytes = next_text;
                let next_depth = depth + 1;
                entries.push(TypeHierarchyEntry {
                    endpoint: next.clone(),
                    depth: next_depth,
                });
                queue.push_back((next.clone(), next_depth));
            }
        }
        entries.sort_by(|left, right| {
            left.depth
                .cmp(&right.depth)
                .then_with(|| left.endpoint.cmp(&right.endpoint))
        });
        Ok(entries)
    }
}

fn validate_endpoint(endpoint: &TypeEndpoint) -> Result<()> {
    ensure!(
        is_relative_file_path(&endpoint.file_path),
        "type endpoint file path must be canonical root-relative"
    );
    ensure!(
        is_qualified_identifier(&endpoint.symbol),
        "type endpoint symbol must be a simple or module-qualified identifier"
    );
    Ok(())
}

fn is_relative_file_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\\')
        && !path.contains(':')
        && !path.bytes().any(|byte| byte == 0)
        && !std::path::Path::new(path).is_absolute()
        && std::path::Path::new(path)
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn is_qualified_identifier(value: &str) -> bool {
    value.split("::").all(is_simple_identifier)
}

fn is_simple_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
        && !value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_digit())
}

fn rust_edges(file_path: &str, source: &str) -> (Vec<TypeHierarchyEdge>, BTreeSet<TypeEndpoint>) {
    let Ok(file) = syn::parse_file(source) else {
        return (Vec::new(), BTreeSet::new());
    };
    let mut collector = RustTypeCollector {
        file_path,
        ..RustTypeCollector::default()
    };
    collector.visit_file(&file);
    (collector.finished, collector.declared)
}

#[derive(Default)]
struct RustScope {
    declarations: BTreeMap<String, Option<RustDeclarationKind>>,
    relationships: Vec<(String, String)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RustDeclarationKind {
    Concrete,
    Trait,
}

#[derive(Default)]
struct RustTypeCollector<'a> {
    file_path: &'a str,
    modules: Vec<String>,
    scopes: Vec<RustScope>,
    finished: Vec<TypeHierarchyEdge>,
    declared: BTreeSet<TypeEndpoint>,
}

impl<'a> RustTypeCollector<'a> {
    fn qualified(&self, name: &str) -> String {
        if self.modules.is_empty() {
            name.to_owned()
        } else {
            format!("{}::{name}", self.modules.join("::"))
        }
    }

    fn scope_mut(&mut self) -> &mut RustScope {
        self.scopes
            .last_mut()
            .expect("Rust type collector always has a scope")
    }

    fn record_declaration(&mut self, name: String, kind: RustDeclarationKind) {
        if !is_simple_identifier(&name) {
            return;
        }
        use std::collections::btree_map::Entry;
        match self.scope_mut().declarations.entry(name) {
            Entry::Vacant(entry) => {
                entry.insert(Some(kind));
            }
            Entry::Occupied(mut entry) => {
                entry.insert(None);
            }
        }
    }

    fn record_impl(&mut self, item: &syn::ItemImpl) {
        if !item.generics.params.is_empty() || item.generics.where_clause.is_some() {
            return;
        }
        let Some((negative, trait_path, _)) = &item.trait_ else {
            return;
        };
        if negative.is_some() {
            return;
        };
        let Some(parent) = simple_path_name(trait_path, true) else {
            return;
        };
        let Some(child) = simple_type_name(&item.self_ty) else {
            return;
        };
        if !is_simple_identifier(&child) || !is_simple_identifier(&parent) {
            return;
        }
        self.scope_mut().relationships.push((child, parent));
    }

    fn record_trait(&mut self, item: &syn::ItemTrait) {
        let child = item.ident.to_string();
        if !is_simple_identifier(&child) {
            return;
        }
        self.record_declaration(child.clone(), RustDeclarationKind::Trait);
        for bound in &item.supertraits {
            let syn::TypeParamBound::Trait(bound) = bound else {
                continue;
            };
            if let Some(parent) = simple_path_name(&bound.path, true) {
                self.scope_mut().relationships.push((child.clone(), parent));
            }
        }
    }

    fn finish_scope(&mut self) {
        let scope = self.scopes.pop().expect("balanced Rust scope stack");
        let declared_names: Vec<String> = scope
            .declarations
            .iter()
            .filter_map(|(name, kind)| kind.is_some().then(|| name.clone()))
            .collect();
        for name in declared_names {
            let symbol = self.qualified(&name);
            self.declared.insert(TypeEndpoint {
                file_path: self.file_path.to_owned(),
                symbol,
            });
        }
        for (child_name, parent_name) in scope.relationships {
            let Some(Some(child_kind)) = scope.declarations.get(&child_name) else {
                continue;
            };
            let Some(Some(parent_kind)) = scope.declarations.get(&parent_name) else {
                continue;
            };
            if !matches!(
                child_kind,
                RustDeclarationKind::Concrete | RustDeclarationKind::Trait
            ) || *parent_kind != RustDeclarationKind::Trait
            {
                continue;
            }
            let child = TypeEndpoint {
                file_path: self.file_path.to_owned(),
                symbol: self.qualified(&child_name),
            };
            let parent = TypeEndpoint {
                file_path: self.file_path.to_owned(),
                symbol: self.qualified(&parent_name),
            };
            if child != parent {
                self.finished.push(TypeHierarchyEdge {
                    child,
                    parent,
                    language: "rust".to_owned(),
                });
            }
        }
    }
}

impl<'ast> Visit<'ast> for RustTypeCollector<'_> {
    fn visit_file(&mut self, file: &'ast syn::File) {
        self.scopes.push(RustScope::default());
        syn::visit::visit_file(self, file);
        self.finish_scope();
    }

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        self.record_declaration(item.ident.to_string(), RustDeclarationKind::Concrete);
    }

    fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
        self.record_declaration(item.ident.to_string(), RustDeclarationKind::Concrete);
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        self.record_trait(item);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        self.record_impl(item);
    }

    fn visit_item_fn(&mut self, _item: &'ast syn::ItemFn) {}

    fn visit_block(&mut self, _block: &'ast syn::Block) {}

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        let Some((_, items)) = &item.content else {
            return;
        };
        let module = item.ident.to_string();
        if !is_simple_identifier(&module) {
            return;
        }
        self.modules.push(module);
        self.scopes.push(RustScope::default());
        for nested in items {
            self.visit_item(nested);
        }
        self.finish_scope();
        self.modules.pop();
    }
}

fn simple_type_name(ty: &syn::Type) -> Option<String> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    simple_path_name(&path.path, path.qself.is_none())
}

fn simple_path_name(path: &syn::Path, qself_is_none: bool) -> Option<String> {
    if !qself_is_none || path.leading_colon.is_some() || path.segments.len() != 1 {
        return None;
    }
    let segment = path.segments.first()?;
    matches!(segment.arguments, syn::PathArguments::None).then(|| segment.ident.to_string())
}

fn python_edges(file_path: &str, source: &str) -> (Vec<TypeHierarchyEdge>, BTreeSet<TypeEndpoint>) {
    let mut declarations = BTreeSet::new();
    let mut relationships = Vec::new();
    let stripped = super::graph::strip_comments_and_strings_hash_family(source);
    let lines: Vec<&str> = stripped.lines().collect();
    let mut index = 0usize;
    while index < lines.len() {
        let code = lines[index].trim_end();
        if code.chars().next().is_some_and(char::is_whitespace) {
            index += 1;
            continue;
        }
        let Some(rest) = code.strip_prefix("class ") else {
            index += 1;
            continue;
        };
        let mut header = rest.to_owned();
        let mut open_parens = paren_delta(rest);
        let mut consumed = 1usize;
        while open_parens > 0
            && consumed < MAX_PYTHON_HEADER_LINES
            && index + consumed < lines.len()
        {
            let continuation = lines[index + consumed].trim();
            header.push(' ');
            header.push_str(continuation);
            if header.len() > MAX_PYTHON_HEADER_BYTES {
                break;
            }
            open_parens += paren_delta(continuation);
            consumed += 1;
        }
        index += consumed;
        if open_parens != 0 || header.len() > MAX_PYTHON_HEADER_BYTES {
            continue;
        }
        let compact: String = header
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        if let Some(child) = compact.strip_suffix(':')
            && is_simple_identifier(child)
        {
            declarations.insert(child.to_owned());
            continue;
        }
        let Some((child, tail)) = compact.split_once('(') else {
            continue;
        };
        let Some(parent) = tail.strip_suffix("):") else {
            continue;
        };
        let parent = parent.strip_suffix(',').unwrap_or(parent);
        if !is_simple_identifier(child) || !is_simple_identifier(parent) {
            continue;
        }
        declarations.insert(child.to_owned());
        relationships.push((child.to_owned(), parent.to_owned()));
    }
    let endpoints = declarations
        .iter()
        .filter_map(|name| TypeEndpoint::new(file_path, name.clone()).ok())
        .collect();
    let edges = relationships
        .into_iter()
        .filter(|(child, parent)| declarations.contains(child) && declarations.contains(parent))
        .filter_map(|(child, parent)| {
            let child = TypeEndpoint::new(file_path, child).ok()?;
            let parent = TypeEndpoint::new(file_path, parent).ok()?;
            (child != parent).then_some(TypeHierarchyEdge {
                child,
                parent,
                language: "python".to_owned(),
            })
        })
        .collect();
    (edges, endpoints)
}

fn paren_delta(value: &str) -> isize {
    value.bytes().fold(0isize, |delta, byte| match byte {
        b'(' => delta.saturating_add(1),
        b')' => delta.saturating_sub(1),
        _ => delta,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sources(rows: &[(&str, Language, &str)]) -> Vec<(String, Language, String)> {
        rows.iter()
            .map(|(path, language, source)| ((*path).into(), *language, (*source).into()))
            .collect()
    }

    fn endpoint(file_path: &str, symbol: &str) -> TypeEndpoint {
        TypeEndpoint::new(file_path, symbol).unwrap()
    }

    #[test]
    fn rust_uses_exact_lexical_scope_for_impls_and_trait_supertraits() {
        let hierarchy = TypeHierarchy::build_bounded(
            &sources(&[(
                "src/types.rs",
                Language::Rust,
                "trait Parent {} trait Child: Parent {} struct Model {} impl Parent for Model {} mod nested { trait Parent {} struct Model {} impl Parent for Model {} }",
            )]),
            10,
        )
        .unwrap();
        assert!(hierarchy.edges().contains(&TypeHierarchyEdge {
            child: endpoint("src/types.rs", "Child"),
            parent: endpoint("src/types.rs", "Parent"),
            language: "rust".into(),
        }));
        assert!(hierarchy.edges().contains(&TypeHierarchyEdge {
            child: endpoint("src/types.rs", "nested::Model"),
            parent: endpoint("src/types.rs", "nested::Parent"),
            language: "rust".into(),
        }));
        let descendants = hierarchy
            .query_bounded(
                &endpoint("src/types.rs", "Parent"),
                TypeHierarchyDirection::Descendants,
                TypeTraversalBudget::default(),
            )
            .unwrap();
        assert_eq!(
            descendants
                .iter()
                .map(|entry| entry.endpoint.symbol.as_str())
                .collect::<Vec<_>>(),
            vec!["Child", "Model"]
        );
    }

    #[test]
    fn rust_never_guesses_root_unique_aliases_negative_or_generic_impls() {
        let hierarchy = TypeHierarchy::build_bounded(
            &sources(&[
                ("src/model.rs", Language::Rust, "struct Model {} impl External for Model {}"),
                ("src/external.rs", Language::Rust, "trait External {}"),
                ("src/alias.rs", Language::Rust, "trait Parent {} type Alias = Parent; struct Other {} impl Alias for Other {}"),
                ("src/generic.rs", Language::Rust, "trait Generic<T> {} struct GenericModel {} impl Generic<u8> for GenericModel {}"),
                ("src/negative.rs", Language::Rust, "trait Parent {} struct Denied {} impl !Parent for Denied {}"),
                ("src/shadow.rs", Language::Rust, "trait Parent {} struct Model {} impl<T> Parent for T {}"),
            ]),
            10,
        )
        .unwrap();
        assert!(hierarchy.edges().is_empty());
    }

    #[test]
    fn rust_local_items_and_duplicate_same_scope_declarations_are_unknown() {
        let hierarchy = TypeHierarchy::build_bounded(
            &sources(&[(
                "src/types.rs",
                Language::Rust,
                "trait Parent {} struct Model {} fn local() { struct Model {} impl Parent for Model {} } struct Duplicate {} struct Duplicate {} impl Parent for Duplicate {}",
            )]),
            10,
        )
        .unwrap();
        assert!(
            hierarchy
                .edges()
                .iter()
                .any(|edge| edge.child.symbol == "Model")
        );
        assert!(
            !hierarchy
                .edges()
                .iter()
                .any(|edge| edge.child.symbol == "Duplicate"),
            "same-scope duplicate declarations must not choose a first endpoint"
        );
        assert!(
            !hierarchy
                .endpoints()
                .contains(&endpoint("src/types.rs", "Duplicate")),
            "ambiguous declarations are not valid query endpoints"
        );
    }

    #[test]
    fn duplicate_nested_names_have_distinct_typed_endpoints() {
        let hierarchy = TypeHierarchy::build_bounded(
            &sources(&[(
                "src/types.rs",
                Language::Rust,
                "mod one { trait Parent {} struct Same {} impl Parent for Same {} } mod two { trait Parent {} struct Same {} impl Parent for Same {} }",
            )]),
            10,
        )
        .unwrap();
        assert!(
            hierarchy
                .edges()
                .iter()
                .any(|edge| edge.child.symbol == "one::Same")
        );
        assert!(
            hierarchy
                .edges()
                .iter()
                .any(|edge| edge.child.symbol == "two::Same")
        );
    }

    #[test]
    fn python_is_top_level_local_and_ignores_comments_strings_and_cross_language_names() {
        let hierarchy = TypeHierarchy::build_bounded(
            &sources(&[
                ("pkg/models.py", Language::Python, "# class Comment(Base):\ntext = '''class String(Base):'''\nclass Parent:\n    pass\nclass Child(Parent):\n    pass\n    class Nested(Parent):\n        pass"),
                ("src/types.rs", Language::Rust, "trait Parent {} struct Child {} impl Parent for Child {}"),
            ]),
            10,
        )
        .unwrap();
        assert!(hierarchy.edges().contains(&TypeHierarchyEdge {
            child: endpoint("pkg/models.py", "Child"),
            parent: endpoint("pkg/models.py", "Parent"),
            language: "python".into(),
        }));
        assert_eq!(
            hierarchy
                .edges()
                .iter()
                .filter(|edge| edge.language == "python")
                .count(),
            1
        );
    }

    #[test]
    fn python_trims_comments_and_accepts_bounded_simple_multiline_headers() {
        let hierarchy = TypeHierarchy::build_bounded(
            &sources(&[(
                "pkg/models.py",
                Language::Python,
                "class Parent: # declaration\r\n    pass\r\nclass Child(\r\n    Parent,\r\n): # relationship\r\n    pass\r\ntext = '''class Fake(\r\nParent,\r\n):'''\r\n    class Nested(\r\n        Parent,\r\n    ):\r\n        pass\r\n",
            )]),
            10,
        )
        .unwrap();
        assert!(hierarchy.edges().contains(&TypeHierarchyEdge {
            child: endpoint("pkg/models.py", "Child"),
            parent: endpoint("pkg/models.py", "Parent"),
            language: "python".into(),
        }));
        assert_eq!(hierarchy.edges().len(), 1);
    }

    #[test]
    fn rust_unsupported_unicode_identifier_is_omitted_without_erasing_valid_edges() {
        let hierarchy = TypeHierarchy::build_bounded(
            &sources(&[
                ("src/unicode.rs", Language::Rust, "trait Parent {} struct Café {} impl Parent for Café {} mod café { trait Parent {} struct Model {} impl Parent for Model {} }"),
                ("src/valid.rs", Language::Rust, "trait Parent {} struct Model {} impl Parent for Model {}"),
            ]),
            10,
        )
        .unwrap();
        assert_eq!(hierarchy.edges().len(), 1);
        assert!(hierarchy.edges().contains(&TypeHierarchyEdge {
            child: endpoint("src/valid.rs", "Model"),
            parent: endpoint("src/valid.rs", "Parent"),
            language: "rust".into(),
        }));
    }

    #[test]
    fn bounded_queries_are_deterministic_cycle_safe_and_validate_exact_endpoints() {
        let a = endpoint("src/types.rs", "A");
        let b = endpoint("src/types.rs", "B");
        let c = endpoint("src/types.rs", "C");
        let hierarchy = TypeHierarchy::from_edges(vec![
            TypeHierarchyEdge {
                child: a.clone(),
                parent: b.clone(),
                language: "rust".into(),
            },
            TypeHierarchyEdge {
                child: b.clone(),
                parent: c.clone(),
                language: "rust".into(),
            },
            TypeHierarchyEdge {
                child: c.clone(),
                parent: a.clone(),
                language: "rust".into(),
            },
        ])
        .unwrap();
        let budget = TypeTraversalBudget {
            max_depth: 8,
            max_nodes: 3,
            max_text_bytes: 100,
            max_work_steps: 8,
        };
        let ancestors = hierarchy
            .query_bounded(&a, TypeHierarchyDirection::Ancestors, budget)
            .unwrap();
        assert_eq!(
            ancestors
                .iter()
                .map(|entry| entry.endpoint.symbol.as_str())
                .collect::<Vec<_>>(),
            vec!["B", "C"]
        );
        assert!(
            hierarchy
                .query_bounded(
                    &endpoint("src/types.rs", "Missing"),
                    TypeHierarchyDirection::Ancestors,
                    budget
                )
                .is_err()
        );
        assert!(
            hierarchy
                .query_bounded(
                    &a,
                    TypeHierarchyDirection::Ancestors,
                    TypeTraversalBudget {
                        max_nodes: 0,
                        ..budget
                    }
                )
                .is_err()
        );
        assert!(
            hierarchy
                .query_bounded(
                    &a,
                    TypeHierarchyDirection::Ancestors,
                    TypeTraversalBudget {
                        max_text_bytes: 1,
                        ..budget
                    }
                )
                .is_err()
        );
        assert!(
            hierarchy
                .query_bounded(
                    &a,
                    TypeHierarchyDirection::Ancestors,
                    TypeTraversalBudget {
                        max_work_steps: 0,
                        ..budget
                    }
                )
                .is_err()
        );
    }

    #[test]
    fn from_parts_rejects_portably_noncanonical_endpoint_paths() {
        for path in [
            "../escape.rs",
            "/absolute.rs",
            "C:/drive.rs",
            "src/nu\0l.rs",
        ] {
            assert!(
                TypeEndpoint::new(path, "Thing").is_err(),
                "must reject {path:?}"
            );
        }
    }

    #[test]
    fn from_parts_requires_every_edge_endpoint_in_the_authoritative_inventory() {
        let child = endpoint("src/types.rs", "Child");
        let parent = endpoint("src/types.rs", "Parent");
        let edge = TypeHierarchyEdge {
            child: child.clone(),
            parent: parent.clone(),
            language: "rust".into(),
        };
        assert!(
            TypeHierarchy::from_parts(vec![edge.clone()], BTreeSet::from([child.clone()])).is_err(),
            "a missing parent must reject the persisted relationship"
        );
        assert!(
            TypeHierarchy::from_parts(vec![edge], BTreeSet::from([parent])).is_err(),
            "a missing child must reject the persisted relationship"
        );
    }

    #[test]
    fn bounded_build_refuses_source_before_parsing_or_retaining_endpoints() {
        let oversized = "x".repeat(DEFAULT_MAX_FILE_BYTES as usize + 1);
        assert!(
            TypeHierarchy::build_bounded(
                &[(String::from("src/large.rs"), Language::Rust, oversized)],
                10,
            )
            .is_err()
        );
    }

    #[test]
    fn bounded_build_refuses_total_source_bytes_before_parsing() {
        let source = "x".repeat(DEFAULT_MAX_FILE_BYTES as usize);
        let sources = (0..17)
            .map(|index| (format!("docs/{index}.txt"), Language::Other, source.clone()))
            .collect::<Vec<_>>();
        assert!(TypeHierarchy::build_bounded(&sources, 10).is_err());
    }
}
