//! PL-04a — Adversarial OCR corpus runner for the paperless ingest gate.
//!
//! Iterates every JSON fixture under
//! `eval/prompt_injection_corpus/paperless_ocr/` and feeds `input_text`
//! into `security::paperless_ingest::ingest_ocr_text`. Asserts the
//! `expected_outcome` documented in each fixture.
//!
//! ## Outcomes
//!
//! - `quarantine` — MUST return `Err(IngestError::Quarantined)`. If
//!   `expected_marker` is set, one finding must contain that substring
//!   (case-insensitive).
//!
//! - `allow_clean` — must return `Ok(payload)` with no
//!   `Finding::PromptInjectionMarker`. False-positive guards.
//!
//! - `known_gap_quarantine_after_pl04` — currently `Ok(_)` because the
//!   sanitizer's marker list does not cover this attack. The runner
//!   asserts the CURRENT behavior so a PL-04 fix that flips the outcome
//!   to Err trips this test — that is the signal to promote the fixture
//!   to `quarantine` in the same PR. This pile IS the PL-04 punch list.
//!
//! Adding a new fixture file is the ONLY change required to extend
//! coverage — no code edits needed.

use neothd::security::ingress_sanitizer::Finding;
use neothd::security::paperless_ingest::{IngestError, OcrSource, ingest_ocr_text};
use serde::Deserialize;
use std::{fs, path::PathBuf};

// ── Fixture schema ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Fixture {
    id: String,
    category: String,
    description: String,
    input_text: String,
    expected_outcome: String,
    #[serde(default)]
    expected_marker: Option<String>,
    #[allow(dead_code)]
    source: String,
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn fixture_paths() -> Vec<PathBuf> {
    let corpus_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("eval/prompt_injection_corpus/paperless_ocr");

    let mut paths: Vec<PathBuf> = fs::read_dir(&corpus_dir)
        .unwrap_or_else(|e| panic!("cannot open corpus dir {corpus_dir:?}: {e}"))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
        .collect();
    paths.sort();
    paths
}

fn load_fixture(path: &PathBuf) -> Fixture {
    let raw = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {path:?}: {e}"))
}

fn finding_matches(findings: &[Finding], needle: &str) -> bool {
    let needle_lc = needle.to_lowercase();
    findings.iter().any(|f| match f {
        Finding::PromptInjectionMarker { pattern } => pattern.to_lowercase().contains(&needle_lc),
        _ => false,
    })
}

// ── Assertion kernels ─────────────────────────────────────────────────────

fn assert_quarantine(fx: &Fixture) {
    match ingest_ocr_text(&fx.input_text, OcrSource::PaperlessNgx, fx.id.clone()) {
        Err(IngestError::Quarantined { findings, .. }) => {
            if let Some(needle) = &fx.expected_marker {
                assert!(
                    finding_matches(&findings, needle),
                    "[{}] quarantine occurred but expected_marker {:?} not found in findings: {:?}",
                    fx.id,
                    needle,
                    findings,
                );
            }
        }
        Ok(payload) => panic!(
            "[{}] expected Quarantined, got Ok — body={:?}, findings={:?}",
            fx.id,
            payload.body(),
            payload.findings,
        ),
    }
}

fn assert_allow_clean(fx: &Fixture) {
    match ingest_ocr_text(&fx.input_text, OcrSource::PaperlessNgx, fx.id.clone()) {
        Ok(payload) => {
            let injection_findings: Vec<_> = payload
                .findings
                .iter()
                .filter(|f| matches!(f, Finding::PromptInjectionMarker { .. }))
                .collect();
            assert!(
                injection_findings.is_empty(),
                "[{}] allow_clean expected no PromptInjectionMarker findings, got: {:?}",
                fx.id,
                injection_findings,
            );
        }
        Err(e) => panic!("[{}] allow_clean expected Ok, got Err: {:?}", fx.id, e),
    }
}

fn assert_known_gap(fx: &Fixture) {
    // Baselines current behavior: sanitizer MUST currently let this
    // through. When PL-04 lands and the gap closes, this test will
    // fail — promote the fixture to expected_outcome: "quarantine"
    // and add the new pattern to the marker list / classifier.
    match ingest_ocr_text(&fx.input_text, OcrSource::PaperlessNgx, fx.id.clone()) {
        Ok(_) => {
            // expected today
        }
        Err(e) => panic!(
            "[{}] known_gap_quarantine_after_pl04 was expected to slip through \
             (current sanitizer baseline), but it was caught: {:?}. \
             PL-04 may have closed this gap — promote the fixture to \
             expected_outcome: \"quarantine\" so it becomes a regression guard.",
            fx.id, e,
        ),
    }
}

// ── Entry point ───────────────────────────────────────────────────────────

#[test]
fn prompt_injection_corpus_paperless_ocr() {
    let paths = fixture_paths();
    assert!(
        !paths.is_empty(),
        "corpus directory is empty — add fixture JSON files"
    );

    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut gap_count = 0usize;

    for path in &paths {
        let fx = load_fixture(path);
        let result = std::panic::catch_unwind(|| match fx.expected_outcome.as_str() {
            "quarantine" => assert_quarantine(&fx),
            "allow_clean" => assert_allow_clean(&fx),
            "known_gap_quarantine_after_pl04" => assert_known_gap(&fx),
            other => panic!("[{}] unknown expected_outcome value: {other:?}", fx.id),
        });

        if fx.expected_outcome == "known_gap_quarantine_after_pl04" {
            gap_count += 1;
        }

        match result {
            Ok(_) => {
                println!(
                    "PASS [{id}] ({cat}, {outcome}) — {desc}",
                    id = fx.id,
                    cat = fx.category,
                    outcome = fx.expected_outcome,
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
                    "FAIL [{id}] ({cat}, {outcome}) — {desc}\n  {msg}",
                    id = fx.id,
                    cat = fx.category,
                    outcome = fx.expected_outcome,
                    desc = fx.description,
                    msg = msg,
                );
                fail += 1;
            }
        }
    }

    println!(
        "\nCorpus result: {pass} PASS / {fail} FAIL / {total} total \
         (including {gap_count} known-gap baselines for PL-04 to close)",
        total = paths.len(),
    );

    assert_eq!(fail, 0, "{fail} fixture(s) failed — see FAIL lines above");
}
