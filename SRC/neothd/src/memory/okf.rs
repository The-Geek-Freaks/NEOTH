//! Open Knowledge Format (OKF) renderer — NEOTH knowledge as portable,
//! Obsidian-native concept documents.
//!
//! Format per the OKF v0.1 spec (GoogleCloudPlatform/knowledge-catalog/okf):
//! each concept is a UTF-8 markdown file with a YAML frontmatter block whose
//! one REQUIRED field is `type`; relations are plain markdown links so
//! Obsidian's graph view, an LLM loading files into context, or any catalog
//! tool can all consume the bundle. We adopt the FORMAT only — NOT the cloud
//! reference agent (Google ADK / Gemini / BigQuery), which is against NEOTH's
//! local-first / self-contained rule.
//!
//! This module is the pure renderer; `cli::okf` walks NEOTH's knowledge
//! (entities + their relations, ground-truth facts) and emits the bundle.

/// A relation to another concept, rendered as a markdown link under `## Related`.
/// `href` is the link target relative to THIS concept's file (e.g. `bob.md` for
/// a sibling, `../facts/3.md` across directories).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OkfLink {
    pub label: String,
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
    pub links: Vec<OkfLink>,
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
        s.push_str("---\n\n");

        if !self.title.is_empty() {
            s.push_str(&format!("# {}\n\n", self.title));
        }
        let body = self.body.trim();
        if !body.is_empty() {
            s.push_str(body);
            s.push_str("\n\n");
        }
        if !self.links.is_empty() {
            s.push_str("## Related\n\n");
            for l in &self.links {
                s.push_str(&format!("- [{}]({})\n", l.label, l.href));
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
            links: vec![OkfLink { label: "Berlin".into(), href: "berlin.md".into() }],
        };
        let md = c.render();
        assert!(md.starts_with("---\ntype: \"entity\"\n"));
        assert!(md.contains("title: \"Alex\""));
        assert!(md.contains("description: \"The operator.\""));
        assert!(md.contains("tags: [\"person\", \"operator\"]"));
        assert!(md.contains("# Alex"));
        assert!(md.contains("Solo dev, security researcher."));
        assert!(md.contains("## Related\n\n- [Berlin](berlin.md)"));
    }

    #[test]
    fn yaml_scalar_escapes_breaking_chars() {
        let c = OkfConcept {
            concept_type: "fact".into(),
            title: String::new(),
            description: Some("role: \"engineer\" # note".into()),
            tags: vec![],
            body: String::new(),
            links: vec![],
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
}
