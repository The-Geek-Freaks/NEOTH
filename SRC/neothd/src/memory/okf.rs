//! Open Knowledge Format (OKF) renderer — NEOTH knowledge as portable,
//! Obsidian-native concept documents.
//!
//! Format per the OKF v0.1 spec (GoogleCloudPlatform/knowledge-catalog/okf):
//! each concept is a UTF-8 markdown file with a YAML frontmatter block whose
//! one REQUIRED field is `type`. Relations are emitted BOTH as machine-readable
//! `relations:` frontmatter edges (robust roundtrip on import) AND as `## Related`
//! markdown links, so Obsidian's graph view, an LLM loading files into context,
//! or any catalog tool can all consume the bundle. We adopt the FORMAT only — NOT the cloud
//! reference agent (Google ADK / Gemini / BigQuery), which is against NEOTH's
//! local-first / self-contained rule.
//!
//! This module is the pure renderer; `cli::okf` walks NEOTH's knowledge
//! (entities + their relations, ground-truth facts) and emits the bundle.

/// A typed relation edge to another concept. Rendered BOTH as machine-readable
/// `relations:` frontmatter (robust roundtrip) AND as a `## Related` markdown
/// link (Obsidian graph). `href` is the target relative to THIS concept's file
/// (e.g. `bob.md` for a sibling).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OkfRelation {
    pub target: String,
    pub relation: String,
    pub href: String,
}

/// One OKF concept document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OkfConcept {
    /// `type` — the one required frontmatter field (the kind of concept).
    pub concept_type: String,
    pub title: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
    /// Markdown body (after the frontmatter). May be empty.
    pub body: String,
    /// Typed relation edges → frontmatter `relations:` + body `## Related` links.
    pub relations: Vec<OkfRelation>,
}

impl OkfConcept {
    /// Render the full `.md` document: frontmatter → title → body → relations.
    pub fn render(&self) -> String {
        let mut s = String::with_capacity(256 + self.body.len());
        s.push_str("---\n");
        s.push_str(&format!("type: {}\n", yaml_scalar(&self.concept_type)));
        if !self.title.is_empty() {
            s.push_str(&format!("title: {}\n", yaml_scalar(&self.title)));
        }
        if let Some(d) = &self.description {
            if !d.is_empty() {
                s.push_str(&format!("description: {}\n", yaml_scalar(d)));
            }
        }
        if !self.tags.is_empty() {
            let tags = self
                .tags
                .iter()
                .map(|t| yaml_scalar(t))
                .collect::<Vec<_>>()
                .join(", ");
            s.push_str(&format!("tags: [{tags}]\n"));
        }
        // Machine-readable relation edges (robust roundtrip; survives manual
        // edits to the body markdown links).
        if !self.relations.is_empty() {
            s.push_str("relations:\n");
            for r in &self.relations {
                s.push_str(&format!(
                    "  - target: {}\n    relation: {}\n    href: {}\n",
                    yaml_scalar(&r.target),
                    yaml_scalar(&r.relation),
                    yaml_scalar(&r.href)
                ));
            }
        }
        s.push_str("---\n\n");

        if !self.title.is_empty() {
            s.push_str(&format!("# {}\n\n", self.title));
        }
        let body = self.body.trim();
        if !body.is_empty() {
            s.push_str(body);
            s.push_str("\n\n");
        }
        if !self.relations.is_empty() {
            s.push_str("## Related\n\n");
            for r in &self.relations {
                s.push_str(&format!("- [{} — {}]({})\n", r.target, r.relation, r.href));
            }
            s.push('\n');
        }
        s
    }
}

/// Sanitize a name into a safe OKF concept-id segment / filename stem:
/// lowercase ASCII alnum + `-`, runs collapsed, trimmed. Empty → `unnamed`.
pub fn slug(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_dash = false;
    for ch in name.trim().chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() {
            out.push(c);
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "unnamed".to_string()
    } else {
        trimmed
    }
}

/// YAML-quote a scalar: always double-quote + escape `\` and `"`, so a value
/// with `:`, `#`, `[`, leading spaces, etc. can never break the frontmatter.
fn yaml_scalar(v: &str) -> String {
    let escaped = v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', " ");
    format!("\"{escaped}\"")
}

/// A parsed OKF concept document (frontmatter + body), for `neoth okf import`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedOkf {
    pub concept_type: String,
    pub title: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub body: String,
    /// Machine-readable relation edges from frontmatter `relations:` (robust;
    /// preferred over body-link parsing on import).
    pub relations: Vec<OkfRelation>,
}

/// Parse an OKF concept `.md` (YAML frontmatter delimited by `---`, then body).
/// `None` if there's no frontmatter or the required `type` field is missing.
/// CRLF-tolerant.
pub fn parse(content: &str) -> Option<ParsedOkf> {
    let norm = content.replace("\r\n", "\n");
    let after_open = norm.trim_start().strip_prefix("---\n")?;
    let close = after_open.find("\n---")?;
    let fm = &after_open[..close];
    let body = after_open[close + 4..]
        .trim_start_matches(['\n', ' '])
        .to_string();
    let val: serde_yaml::Value = serde_yaml::from_str(fm).ok()?;
    let concept_type = val.get("type")?.as_str()?.trim().to_string();
    if concept_type.is_empty() {
        return None;
    }
    let title = val
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let description = val
        .get("description")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let tags = val
        .get("tags")
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|t| t.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let relations = val
        .get("relations")
        .and_then(|v| serde_yaml::from_value::<Vec<OkfRelation>>(v.clone()).ok())
        .unwrap_or_default();
    Some(ParsedOkf {
        concept_type,
        title,
        description,
        tags,
        body,
        relations,
    })
}

/// Extract the `## Related` markdown links from a concept body — `(label, href)`
/// per `- [label](href)` line. Used by `neoth okf import` to rebuild relations.
pub fn parse_related_links(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in body.lines() {
        let l = line.trim();
        let Some(rest) = l.strip_prefix("- [") else {
            continue;
        };
        let Some(close) = rest.find("](") else {
            continue;
        };
        let label = rest[..close].to_string();
        let after = &rest[close + 2..];
        if let Some(end) = after.find(')') {
            out.push((label, after[..end].to_string()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_required_type_and_frontmatter() {
        let c = OkfConcept {
            concept_type: "entity".into(),
            title: "Alex".into(),
            description: Some("The operator.".into()),
            tags: vec!["person".into(), "operator".into()],
            body: "Solo dev, security researcher.".into(),
            relations: vec![OkfRelation {
                target: "Berlin".into(),
                relation: "lives_in".into(),
                href: "berlin.md".into(),
            }],
        };
        let md = c.render();
        assert!(md.starts_with("---\ntype: \"entity\"\n"));
        assert!(md.contains("title: \"Alex\""));
        assert!(md.contains("description: \"The operator.\""));
        assert!(md.contains("tags: [\"person\", \"operator\"]"));
        // machine-readable frontmatter edge
        assert!(md.contains("relations:\n  - target: \"Berlin\""));
        assert!(md.contains("relation: \"lives_in\""));
        assert!(md.contains("# Alex"));
        assert!(md.contains("Solo dev, security researcher."));
        // + Obsidian markdown link
        assert!(md.contains("## Related\n\n- [Berlin — lives_in](berlin.md)"));
    }

    #[test]
    fn yaml_scalar_escapes_breaking_chars() {
        let c = OkfConcept {
            concept_type: "fact".into(),
            title: String::new(),
            description: Some("role: \"engineer\" # note".into()),
            tags: vec![],
            body: String::new(),
            relations: vec![],
        };
        let md = c.render();
        // The colon/hash/quotes are inside a quoted scalar → still valid YAML.
        assert!(md.contains("description: \"role: \\\"engineer\\\" # note\""));
        assert!(!md.contains("# Related")); // no links, no title
    }

    #[test]
    fn slug_sanitizes() {
        assert_eq!(slug("Alex Kovic"), "alex-kovic");
        assert_eq!(slug("  C++ / Rust!  "), "c-rust");
        assert_eq!(slug("###"), "unnamed");
        assert_eq!(slug("already-slug"), "already-slug");
    }

    #[test]
    fn render_then_parse_roundtrips() {
        let c = OkfConcept {
            concept_type: "fact".into(),
            title: "A title".into(),
            description: Some("one-sentence summary".into()),
            tags: vec!["operator".into(), "verified".into()],
            body: "Some body text.".into(),
            relations: vec![],
        };
        let p = parse(&c.render()).expect("parse own render");
        assert_eq!(p.concept_type, "fact");
        assert_eq!(p.title, "A title");
        assert_eq!(p.description.as_deref(), Some("one-sentence summary"));
        assert_eq!(p.tags, vec!["operator".to_string(), "verified".to_string()]);
        assert!(p.body.contains("Some body text."));
    }

    #[test]
    fn relations_roundtrip_through_frontmatter() {
        // A target whose name itself contains " — " (the body-link separator):
        // the machine-readable frontmatter must survive it intact, where the
        // markdown-link fallback parser would split on the wrong dash.
        let c = OkfConcept {
            concept_type: "entity".into(),
            title: "Alex".into(),
            description: None,
            tags: vec![],
            body: "operator".into(),
            relations: vec![OkfRelation {
                target: "Bob — the builder".into(),
                relation: "knows".into(),
                href: "bob-the-builder.md".into(),
            }],
        };
        let p = parse(&c.render()).expect("parse own render");
        assert_eq!(p.relations.len(), 1);
        assert_eq!(p.relations[0].target, "Bob — the builder");
        assert_eq!(p.relations[0].relation, "knows");
        assert_eq!(p.relations[0].href, "bob-the-builder.md");
    }

    #[test]
    fn parse_related_links_extracts_pairs() {
        let body = "# X\n\n## Related\n\n- [Bob — knows](bob.md)\n- [Berlin — lives_in](berlin.md)\nnot a link\n";
        let links = parse_related_links(body);
        assert_eq!(links.len(), 2);
        assert_eq!(links[0], ("Bob — knows".to_string(), "bob.md".to_string()));
        assert_eq!(links[1].0, "Berlin — lives_in");
    }

    #[test]
    fn parse_rejects_no_frontmatter_and_crlf_ok() {
        assert!(parse("plain text, no frontmatter").is_none());
        // CRLF frontmatter still parses (the repo writes CRLF on Windows).
        let p = parse("---\r\ntype: entity\r\ntitle: X\r\n---\r\n\r\nbody").expect("crlf");
        assert_eq!(p.concept_type, "entity");
        assert_eq!(p.title, "X");
    }
}
