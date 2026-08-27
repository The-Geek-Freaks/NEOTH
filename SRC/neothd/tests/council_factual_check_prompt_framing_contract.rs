//! GOLD-R3-14 factual-check prompt framing source contract.

const ENVELOPE: &str = include_str!("../src/security/prompt_envelope.rs");
const FACTUAL_CHECK: &str = include_str!("../src/council/factual_check.rs");
const ORCHESTRATOR: &str = include_str!("../src/council/orchestrator.rs");

const TRY_EMBED_GROUND_TRUTH_TAG_DECLARATION: &str = "pubfntry_embed_ground_truth_tag(prompt:&str,assertions:&[FactualAssertion],)->Result<String,crate::security::PromptBuildError>";
const FACTUAL_CONTRADICTION_CHECK_DECLARATION: &str = "pubfnfactual_contradiction_check(response:&str,assertions:&[FactualAssertion],negation_markers:&[&str],window_chars:usize,)->FactualCheckOutcome";

fn function_body(source: &str, signature: &str) -> String {
    let code = code_only(source);
    let start = code_signature_offset(&code, signature)
        .unwrap_or_else(|| panic!("missing function signature: {signature}"));
    let open = code_open_brace_offset(&code, start + signature.len())
        .unwrap_or_else(|| panic!("missing function body: {signature}"));
    function_body_from_open(&code, open, signature)
}

fn public_function_body(source: &str, name: &str, expected_declaration: &str) -> String {
    let code = code_only(source);
    let function_marker = format!("fn {name}");
    let function_start = code_signature_offset(&code, &function_marker)
        .unwrap_or_else(|| panic!("missing function item: {name}"));
    let declaration_start = code[..function_start]
        .rfind("pub")
        .unwrap_or_else(|| panic!("missing public visibility for function item: {name}"));
    let open = code_open_brace_offset(&code, function_start + function_marker.len())
        .unwrap_or_else(|| panic!("missing function body: {name}"));
    let actual_declaration: String = code[declaration_start..open]
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    assert_eq!(
        actual_declaration, expected_declaration,
        "public function declaration drifted: {name}"
    );
    function_body_from_open(&code, open, name)
}

fn function_body_from_open(code: &str, open: usize, description: &str) -> String {
    let bytes = code.as_bytes();
    let mut depth = 0usize;
    let mut index = open;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'{' {
            depth += 1;
        } else if byte == b'}' {
            depth -= 1;
            if depth == 0 {
                return code[open + 1..index].to_string();
            }
        }
        index += 1;
    }
    panic!("unterminated function body: {description}");
}

/// Blank Rust comments and quoted literals without moving code offsets. This
/// prevents a source-gate decoy from redirecting function extraction.
fn code_only(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut code = bytes.to_vec();
    let mut index = 0usize;
    while index < bytes.len() {
        let end = if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            bytes[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|offset| index + offset)
                .unwrap_or(bytes.len())
        } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            nested_block_comment_end(bytes, index)
        } else if let Some(end) = raw_string_end(bytes, index) {
            end
        } else if bytes[index] == b'\"' {
            quoted_literal_end(bytes, index, b'\"')
        } else if is_char_literal_start(bytes, index) {
            quoted_literal_end(bytes, index, b'\'')
        } else {
            index += 1;
            continue;
        };
        code[index..end].fill(b' ');
        index = end;
    }
    String::from_utf8(code).expect("source bytes remain valid UTF-8 after masking")
}

fn nested_block_comment_end(bytes: &[u8], start: usize) -> usize {
    let mut depth = 1usize;
    let mut index = start + 2;
    while index < bytes.len() {
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            depth += 1;
            index += 2;
        } else if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
            depth -= 1;
            index += 2;
            if depth == 0 {
                return index;
            }
        } else {
            index += 1;
        }
    }
    bytes.len()
}

fn raw_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let raw_start = match bytes.get(start..) {
        Some([b'r', ..]) => start,
        Some([b'b', b'r', ..]) => start + 1,
        _ => return None,
    };
    let mut quote = raw_start + 1;
    while bytes.get(quote) == Some(&b'#') {
        quote += 1;
    }
    if bytes.get(quote) != Some(&b'\"') {
        return None;
    }
    let hashes = quote - raw_start - 1;
    let closing_width = hashes.checked_add(1)?;
    let mut index = quote + 1;
    while index < bytes.len() {
        let closing_end = index.checked_add(closing_width)?;
        if bytes[index] == b'\"'
            && bytes
                .get(index + 1..closing_end)
                .map(|suffix| suffix.iter().all(|byte| *byte == b'#'))
                .unwrap_or(false)
        {
            return Some(closing_end);
        }
        index += 1;
    }
    Some(bytes.len())
}

fn quoted_literal_end(bytes: &[u8], start: usize, quote: u8) -> usize {
    let mut index = start + 1;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index += 2;
        } else if bytes[index] == quote {
            return index + 1;
        } else {
            index += 1;
        }
    }
    bytes.len()
}

fn is_char_literal_start(bytes: &[u8], start: usize) -> bool {
    if bytes.get(start) != Some(&b'\'') {
        return false;
    }
    let Some(next) = bytes.get(start + 1) else {
        return false;
    };
    *next == b'\\' || bytes.get(start + 2) == Some(&b'\'')
}

fn code_signature_offset(source: &str, signature: &str) -> Option<usize> {
    source
        .as_bytes()
        .windows(signature.len())
        .position(|window| window == signature.as_bytes())
}

fn code_open_brace_offset(source: &str, start: usize) -> Option<usize> {
    source.as_bytes()[start..]
        .iter()
        .position(|byte| *byte == b'{')
        .map(|offset| start + offset)
}

#[test]
fn function_body_ignores_comment_and_string_signature_decoys() {
    let source = r##"
        // pub fn selected() { return \"comment decoy\"; }
        const DECOY: &str = "pub fn selected() { return \"string decoy\"; }";
        const RAW_DECOY: &str = r#"unescaped " pub fn selected() { } "#;
        /* outer /* pub fn selected() { } */ still a comment */
        pub fn selected()
        /* { body-open decoy } */ {
            let structured = "{ not a code brace }";
            if true {
                return "real body";
            }
            "unreachable"
        }
    "##;

    let body = function_body(source, "pub fn selected()");
    assert!(body.contains("let structured"));
    assert!(body.contains("if true"));
    assert!(!body.contains("pub fn selected"));
}

#[test]
fn code_only_starts_char_literals_at_the_opening_quote() {
    let source = r#"
        let quote = '"';
        let suffix = prompt.rfind("\n\n[GROUND_TRUTH]\n")?;
        pub fn selected() {}
    "#;
    let opening_quote = source.find('\'').expect("fixture has a char literal");

    assert!(
        !is_char_literal_start(source.as_bytes(), opening_quote - 2),
        "only an apostrophe may begin a character literal"
    );
    assert!(is_char_literal_start(source.as_bytes(), opening_quote));
    assert!(
        code_only(source).contains("pub fn selected()"),
        "a character literal must not hide following function items"
    );
}

#[test]
fn factual_check_has_separate_typed_question_and_assertion_purposes() {
    for required in [
        "CouncilGroundTruthQuestion",
        "CouncilGroundTruthAssertions",
        "Self::CouncilGroundTruthQuestion => &[PromptFieldKind::OriginalQuestion]",
        "Self::CouncilGroundTruthAssertions => &[PromptFieldKind::GroundTruthAssertions]",
        "\"council_ground_truth_question\"",
        "\"council_ground_truth_assertions\"",
        "Self::GroundTruthAssertions => MAX_QA_CONTRACT_BYTES",
    ] {
        assert!(
            ENVELOPE.contains(required),
            "missing factual-check envelope invariant: {required}"
        );
    }
}

#[test]
fn factual_check_serializes_each_provider_bound_value_once_without_raw_fallback() {
    let builder = public_function_body(
        FACTUAL_CHECK,
        "try_embed_ground_truth_tag",
        TRY_EMBED_GROUND_TRUTH_TAG_DECLARATION,
    );
    assert_eq!(
        builder.matches("serialize_untrusted_prompt(").count(),
        2,
        "question and assertions must each cross one typed boundary"
    );
    for required in [
        "PromptEnvelopePurpose::CouncilGroundTruthQuestion",
        "PromptEnvelopePurpose::CouncilGroundTruthAssertions",
        "PromptFieldKind::OriginalQuestion",
        "PromptFieldKind::GroundTruthAssertions",
        "PromptEnvelopeError::Serialization",
        "preflight_assertions_json(assertions)?",
    ] {
        assert!(
            builder.contains(required),
            "missing factual framing control: {required}"
        );
    }
    let preflight = builder
        .find("preflight_assertions_json(assertions)?")
        .unwrap();
    let serialize = builder.find("serde_json::to_string(assertions)").unwrap();
    assert!(
        preflight < serialize,
        "bound assertions before JSON allocation"
    );
}

#[test]
fn orchestrator_rejects_framing_before_provider_scheduling_or_budget_charge() {
    let preflight = function_body(ORCHESTRATOR, "pub async fn run_debate_with_depth_budget(");
    let validate = preflight
        .find("try_embed_ground_truth_tag(prompt, assertions)")
        .unwrap();
    let scheduler = preflight.find("let mut tasks: FuturesUnordered").unwrap();
    let provider = preflight.find("run_one(").unwrap();
    assert!(validate < scheduler && scheduler < provider);
    assert!(preflight.contains("Verdict::QuorumFailed"));
    assert!(!preflight.contains("Cow::Borrowed(prompt)"));
}

#[test]
fn adversarial_limits_and_local_only_candidate_comparison_are_pinned() {
    let local_comparison = public_function_body(
        FACTUAL_CHECK,
        "factual_contradiction_check",
        FACTUAL_CONTRADICTION_CHECK_DECLARATION,
    );
    let adversarial_prompt = function_body(
        FACTUAL_CHECK,
        "fn typed_factual_prompt_escapes_adversarial_fields_and_keeps_suffix_degradable()",
    );
    let limits = function_body(
        FACTUAL_CHECK,
        "fn oversized_typed_factual_fields_fail_closed_without_raw_fallback()",
    );
    let pre_provider_rejection = function_body(
        ORCHESTRATOR,
        "async fn oversized_factual_question_rejects_before_provider_or_budget()",
    );
    for required in [
        "try_embed_ground_truth_tag(",
        "strip_ground_truth_suffix(",
        "envelope_field_data(",
    ] {
        assert!(
            adversarial_prompt.contains(required),
            "missing adversarial prompt behavior token: {required}"
        );
    }
    assert!(limits.contains("large_ascii_assertions"));
    assert!(limits.contains("control_heavy_assertions"));
    assert!(pre_provider_rejection.contains("assert_eq!(budget.used(), 0)"));
    assert!(
        !local_comparison.contains(".ask("),
        "candidate responses are local-only comparisons, not a provider sink"
    );
}
