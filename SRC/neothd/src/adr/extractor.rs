//! Detect decision markers in a provider response and pull out the ADR
//! body — Phase 31 R-21 ADR-1.
//!
//! Looks for any of these markers at the start of a line (case-insensitive):
//!   - `DECISION:`
//!   - `Beschluss:`   (German equivalent — the operator's primary language)
//!   - `ADR:`
//!
//! Each marker line plus subsequent non-blank lines until a blank line OR
//! a new marker becomes one Decision. The first non-marker non-blank line
//! is the title (first line of the marker text, truncated to 80 chars).

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    /// First line of the decision text, used for filename + ADR title.
    pub title: String,
    /// Full decision body verbatim (marker stripped).
    pub body: String,
}

const MARKERS: &[&str] = &["DECISION:", "Beschluss:", "ADR:"];

/// Pull every decision out of `response`. Returns in document order.
pub fn extract_decisions(response: &str) -> Vec<Decision> {
    let mut out = Vec::new();
    let mut current: Option<(String, Vec<String>)> = None;

    for line in response.lines() {
        if let Some(rest) = strip_marker(line) {
            // Flush the previous decision before starting a new one.
            if let Some((title, body_lines)) = current.take() {
                out.push(build_decision(title, body_lines));
            }
            let trimmed = rest.trim();
            let title = first_sentence(trimmed);
            current = Some((title, vec![trimmed.to_string()]));
        } else if let Some((_, body_lines)) = current.as_mut() {
            if line.trim().is_empty() {
                // Blank line terminates the current decision.
                if let Some((title, body)) = current.take() {
                    out.push(build_decision(title, body));
                }
            } else {
                body_lines.push(line.to_string());
            }
        }
    }
    if let Some((title, body_lines)) = current.take() {
        out.push(build_decision(title, body_lines));
    }
    out.into_iter()
        .filter(|d| !d.body.trim().is_empty())
        .collect()
}

fn strip_marker(line: &str) -> Option<&str> {
    let lower = line.trim_start();
    for m in MARKERS {
        if lower.len() >= m.len() && lower[..m.len()].eq_ignore_ascii_case(m) {
            return Some(&lower[m.len()..]);
        }
    }
    None
}

fn first_sentence(s: &str) -> String {
    let line: String = s
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .chars()
        .take(80)
        .collect();
    if line.is_empty() {
        "untitled-decision".to_string()
    } else {
        line
    }
}

fn build_decision(title: String, body_lines: Vec<String>) -> Decision {
    Decision {
        title,
        body: body_lines.join("\n").trim().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_single_decision_with_decision_marker() {
        let resp = "Some context.\n\nDECISION: Use rusqlite bundled mode.\n\nFurther rationale.";
        let ds = extract_decisions(resp);
        assert_eq!(ds.len(), 1);
        assert_eq!(ds[0].title, "Use rusqlite bundled mode.");
        assert!(ds[0].body.starts_with("Use rusqlite bundled"));
    }

    #[test]
    fn extracts_german_beschluss_marker() {
        let resp = "Beschluss: WAL-Rotation bei 16 MiB / 24h.";
        let ds = extract_decisions(resp);
        assert_eq!(ds.len(), 1);
        assert!(ds[0].title.contains("WAL-Rotation"));
    }

    #[test]
    fn case_insensitive_marker_match() {
        let resp = "decision: lowercase still counts";
        let ds = extract_decisions(resp);
        assert_eq!(ds.len(), 1);
    }

    #[test]
    fn multiple_decisions_separated_by_blank_lines() {
        let resp = "\
DECISION: First decision body.

DECISION: Second decision body.

unrelated trailing text.";
        let ds = extract_decisions(resp);
        assert_eq!(ds.len(), 2);
        assert!(ds[0].title.starts_with("First"));
        assert!(ds[1].title.starts_with("Second"));
    }

    #[test]
    fn multiline_body_kept_intact() {
        let resp = "\
ADR: Adopt the new schema
The rationale spans
three lines of detail
without a blank between.

Next thing.";
        let ds = extract_decisions(resp);
        assert_eq!(ds.len(), 1);
        assert!(ds[0].body.contains("three lines"));
    }

    #[test]
    fn no_marker_no_decisions() {
        let ds = extract_decisions("just a regular reply with no marker at all.");
        assert!(ds.is_empty());
    }

    #[test]
    fn title_truncated_at_80_chars() {
        let long = "a".repeat(200);
        let resp = format!("DECISION: {long}");
        let ds = extract_decisions(&resp);
        assert_eq!(ds[0].title.chars().count(), 80);
    }

    #[test]
    fn empty_decision_body_dropped() {
        let resp = "DECISION:    \n\nDECISION: real one";
        let ds = extract_decisions(resp);
        assert_eq!(ds.len(), 1);
        assert!(ds[0].title.contains("real"));
    }
}
