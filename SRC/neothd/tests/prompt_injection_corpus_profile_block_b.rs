//! ADV-03 prompt-injection regression corpus — profile Block-B.
//!
//! Iterates every JSON fixture under
//! `eval/prompt_injection_corpus/profile_block_b/` and verifies the
//! two concrete defences:
//!
//!   • `skip_extraction` — `is_quoted_content` must return `true`,
//!     proving `extract()` would short-circuit before calling the LLM.
//!
//!   • `xml_escape` — `render_for_synthesis_prompt` must not contain
//!     any unescaped `<` or `>` characters inside the rendered block
//!     (beyond the known-good structural tags we emit ourselves).
//!
//! Adding a new fixture file is the ONLY change required to extend
//! coverage — no code edits needed.

use neothd::profile::extract::is_quoted_content;
use neothd::profile::lookup::{PROFILE_BOUNDARY_HEADER, ProfileClaim, render_for_synthesis_prompt};
use serde::Deserialize;
use std::{fs, path::PathBuf};

// ── Fixture schema ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Fixture {
    id: String,
    category: String,
    description: String,
    input_text: String,
    expected_defence: String,
    expected_evidence: String,
    source: String,
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Collect all fixture paths from the corpus directory.
fn fixture_paths() -> Vec<PathBuf> {
    // Resolve relative to the workspace root (the cwd when `cargo test` runs).
    let corpus_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // SRC/
        .unwrap()
        .parent() // AGENTER/
        .unwrap()
        .join("eval/prompt_injection_corpus/profile_block_b");

    let mut paths: Vec<PathBuf> = fs::read_dir(&corpus_dir)
        .unwrap_or_else(|e| panic!("cannot open corpus dir {corpus_dir:?}: {e}"))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
        .collect();
    paths.sort();
    paths
}

/// Parse a fixture JSON file; panics with the file name on error.
fn load_fixture(path: &PathBuf) -> Fixture {
    let raw = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {path:?}: {e}"))
}

/// Build the minimal claim list needed to exercise render_for_synthesis_prompt.
/// Uses the hostile `input_text` as the claim value so the render path
/// is exercised under adversarial input.
fn make_claims(input_text: &str) -> Vec<ProfileClaim> {
    vec![ProfileClaim {
        field: "bio".to_string(),
        value_json: serde_json::to_string(input_text).unwrap(),
        confidence: 0.95,
    }]
}

// ── Assertion kernels ─────────────────────────────────────────────────────

/// `skip_extraction`: `is_quoted_content` must return true for the
/// hostile text. In production, `extract()` checks this and returns
/// zero claims without calling the LLM.
fn assert_skip_extraction(fx: &Fixture) {
    assert!(
        is_quoted_content(&fx.input_text),
        "[{}] skip_extraction FAIL — is_quoted_content returned false.\n\
         description: {}\n\
         evidence hint: {}",
        fx.id,
        fx.description,
        fx.expected_evidence,
    );
}

/// `xml_escape`: render_for_synthesis_prompt must not emit any raw `<`
/// or `>` characters inside the rendered value (i.e., after the opening
/// `<profile_claim ...>` tag we write ourselves). We verify this by
/// stripping the known-structural tags produced by the renderer and then
/// checking that no bare angle bracket remains.
fn assert_xml_escape(fx: &Fixture) {
    let claims = make_claims(&fx.input_text);
    let rendered = render_for_synthesis_prompt(&claims);

    // The boundary header must still lead the block.
    assert!(
        rendered.starts_with(PROFILE_BOUNDARY_HEADER),
        "[{}] xml_escape FAIL — PROFILE_BOUNDARY_HEADER missing from rendered block",
        fx.id,
    );

    // Strip all structural tags that the renderer ITSELF emits so we
    // only examine what came from the hostile input.
    let stripped = rendered
        .replace(PROFILE_BOUNDARY_HEADER, "")
        .replace("<profile_context>", "")
        .replace("</profile_context>", "")
        // The opening profile_claim tag (with our attributes).
        // We use a simple heuristic: remove everything between the
        // outermost `<profile_claim` and the matching `>`.
        ;
    // Remove the structural opening tag (greedy is fine here — one claim).
    let stripped = {
        let start = stripped.find("<profile_claim");
        let end = stripped.find('>');
        match (start, end) {
            (Some(s), Some(e)) if s < e => {
                let mut s2 = stripped.clone();
                s2.replace_range(s..=e, "");
                s2
            }
            _ => stripped,
        }
    };
    // Remove the structural closing tag.
    let stripped = stripped.replace("</profile_claim>", "");

    // After stripping our own structural tags the remaining text must
    // contain no raw `<` or `>` — only `&lt;` / `&gt;` entity forms.
    assert!(
        !stripped.contains('<') && !stripped.contains('>'),
        "[{}] xml_escape FAIL — raw angle bracket leaked in rendered claim value.\n\
         description: {}\n\
         evidence hint: {}\n\
         stripped content: {:?}",
        fx.id,
        fx.description,
        fx.expected_evidence,
        stripped,
    );
}

// ── Entry point ───────────────────────────────────────────────────────────

#[test]
fn prompt_injection_corpus_profile_block_b() {
    let paths = fixture_paths();
    assert!(
        !paths.is_empty(),
        "corpus directory is empty — add fixture JSON files"
    );

    let mut pass = 0usize;
    let mut fail = 0usize;

    for path in &paths {
        let fx = load_fixture(path);
        let result = std::panic::catch_unwind(|| match fx.expected_defence.as_str() {
            "skip_extraction" => assert_skip_extraction(&fx),
            "xml_escape" => assert_xml_escape(&fx),
            other => panic!("[{}] unknown expected_defence value: {other:?}", fx.id),
        });

        match result {
            Ok(_) => {
                println!(
                    "PASS [{id}] ({cat}) — {desc}",
                    id = fx.id,
                    cat = fx.category,
                    desc = fx.description,
                );
                pass += 1;
            }
            Err(e) => {
                let msg = if let Some(s) = e.downcast_ref::<String>() {
                    s.clone()
                } else if let Some(s) = e.downcast_ref::<&str>() {
                    s.to_string()
                } else {
                    "(non-string panic payload)".to_string()
                };
                eprintln!(
                    "FAIL [{id}] ({cat}) — {desc}\n  {msg}",
                    id = fx.id,
                    cat = fx.category,
                    desc = fx.description,
                    msg = msg,
                );
                fail += 1;
            }
        }
    }

    println!(
        "\nCorpus result: {pass} PASS / {fail} FAIL / {} total",
        paths.len()
    );

    assert_eq!(fail, 0, "{fail} fixture(s) failed — see FAIL lines above");
}
