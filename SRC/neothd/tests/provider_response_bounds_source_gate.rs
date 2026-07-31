//! Source tripwires for bounded provider response envelopes (GOLD-R4-15k1).
//!
//! Two transports have adopted the shared `response_bounds` readers. These
//! tests pin that adoption so a later refactor cannot quietly reintroduce an
//! unbounded `.json()`/`.text()` read, a raw-body log line, or a skip-and-
//! synthesize-success frame path.
//!
//! `PENDING` is the ratchet: every adapter still listed there is known to be
//! unbounded, and the gate fails the moment one of them starts using the
//! shared readers without being promoted to a real assertion block here. That
//! is what keeps the roadmap item honest — it cannot close while `PENDING` is
//! non-empty, and it cannot be closed by accident either.

const RESPONSE_BOUNDS: &str = include_str!("../src/providers/response_bounds.rs");
const OPENAI: &str = include_str!("../src/providers/openai_api.rs");
const OLLAMA: &str = include_str!("../src/providers/ollama_api.rs");
const ANTHROPIC: &str = include_str!("../src/providers/anthropic_api.rs");
const GEMINI: &str = include_str!("../src/providers/gemini_api.rs");
const COHERE: &str = include_str!("../src/providers/cohere_api.rs");
const AZURE: &str = include_str!("../src/providers/azure_openai.rs");
const BEDROCK: &str = include_str!("../src/providers/aws_bedrock.rs");
const COPILOT: &str = include_str!("../src/providers/copilot.rs");

/// Adapters that have NOT yet adopted the shared bounded readers.
const PENDING: &[(&str, &str)] = &[
    (
        "claude_cli.rs",
        include_str!("../src/providers/claude_cli.rs"),
    ),
    (
        "recursive_mas.rs",
        include_str!("../src/providers/recursive_mas.rs"),
    ),
];

/// Everything before the file's `#[cfg(test)] mod tests` block. Fixtures may
/// legitimately hand-roll a response; production code may not.
fn production(source: &str) -> &str {
    match source.rfind("mod tests {") {
        Some(end) => &source[..end],
        None => source,
    }
}

fn assert_no_unbounded_response_reads(name: &str, source: &str) {
    let production = production(source);
    // Match the awaited form so `str::bytes()` and friends are not confused
    // with a `reqwest::Response` read, and normalize whitespace so rustfmt's
    // line breaks between the call and its `.await` cannot hide one.
    // Line comments are dropped first: a doc comment that mentions the old
    // unbounded call while explaining the replacement is not a violation.
    let dense: String = production
        .lines()
        .map(|line| match line.find("//") {
            Some(comment) => &line[..comment],
            None => line,
        })
        .flat_map(str::chars)
        .filter(|character| !character.is_whitespace())
        .collect();
    for (call, what) in [
        (".json().await", "deserializes"),
        (".text().await", "buffers"),
        (".bytes().await", "collects"),
        (".chunk().await", "streams"),
    ] {
        assert!(
            !dense.contains(call),
            "{name}: Response{call} {what} an attacker-controlled body with no size cap"
        );
    }
    assert!(
        !production.contains("raw = %"),
        "{name}: provider-controlled bytes must never reach a tracing field"
    );
}

#[test]
fn shared_primitives_pin_their_caps() {
    assert!(
        RESPONSE_BOUNDS
            .contains("pub(crate) const MAX_SUCCESS_JSON_BODY_BYTES: usize = 8 * 1024 * 1024;")
    );
    assert!(RESPONSE_BOUNDS.contains("pub(crate) const MAX_SSE_FRAME_BYTES: usize = 1024 * 1024;"));
    assert!(RESPONSE_BOUNDS.contains("pub(crate) async fn error_body_evidence("));
    assert!(RESPONSE_BOUNDS.contains("pub(crate) async fn decode_json<"));
    assert!(RESPONSE_BOUNDS.contains("pub(crate) fn append_frame_segment("));
    assert!(RESPONSE_BOUNDS.contains("pub(crate) fn frame_utf8<"));
    // Evidence must be a digest, never the bytes themselves.
    assert!(
        RESPONSE_BOUNDS.contains("bounded_audit_digest_bytes(domain, slices, input_truncated)")
    );
}

#[test]
fn openai_compatible_transport_stays_bounded() {
    assert_no_unbounded_response_reads("openai_api.rs", OPENAI);
    let production = production(OPENAI);
    assert!(production.contains("response_bounds::decode_json("));
    assert!(production.contains("response_bounds::append_frame_segment("));
    assert!(production.contains("response_bounds::frame_utf8("));
    assert!(production.contains("const MAX_PROVIDER_ERROR_BODY_BYTES: usize = 64 * 1024;"));
    assert!(production.contains(
        "MAX_PROVIDER_SUCCESS_BODY_BYTES: usize = response_bounds::MAX_SUCCESS_JSON_BODY_BYTES;"
    ));
}

#[test]
fn ollama_transport_stays_bounded() {
    assert_no_unbounded_response_reads("ollama_api.rs", OLLAMA);
    let production = production(OLLAMA);
    assert!(production.contains("response_bounds::decode_json("));
    assert!(production.contains("response_bounds::append_frame_segment("));
    assert!(production.contains("response_bounds::frame_utf8("));
    assert!(production.contains("const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;"));
    assert_eq!(
        production
            .matches("response_bounds::error_body_evidence(")
            .count(),
        2,
        "both the complete() and stream() handshake error paths must read a capped body"
    );
}

/// The pre-change adapter logged a malformed NDJSON line raw, skipped it, and
/// still emitted the synthetic done terminator — reporting a finished
/// generation after silently losing output.
#[test]
fn ollama_malformed_frames_fail_closed_instead_of_skipping() {
    let production = production(OLLAMA);
    assert!(production.contains("malformed NDJSON frame"));
    assert!(
        !production.contains("chunk parse error; skipping"),
        "a malformed frame must fail the stream, not be skipped"
    );
    assert!(
        !production.contains("dropping tail"),
        "a malformed EOF residual must fail the stream, not be dropped"
    );
    // The frame decoder is the single funnel for both the newline-delimited
    // and the newline-less final frame.
    assert_eq!(
        production.matches("decode_ndjson_frame(").count(),
        3,
        "one definition plus the in-loop and EOF-residual call sites"
    );
}

/// Anthropic and Gemini are single-shot JSON transports: no frame primitives,
/// but the success body, the error body and the retained quota evidence all
/// have to go through the bounded readers.
#[test]
fn single_shot_json_transports_stay_bounded() {
    for (name, source, error_domain, success_domain) in [
        (
            "anthropic_api.rs",
            ANTHROPIC,
            "anthropic-http-error-body/v1",
            "anthropic-success-body/v1",
        ),
        (
            "gemini_api.rs",
            GEMINI,
            "gemini-http-error-body/v1",
            "gemini-success-body/v1",
        ),
        (
            "cohere_api.rs",
            COHERE,
            "cohere-http-error-body/v1",
            "cohere-success-body/v1",
        ),
        (
            "azure_openai.rs",
            AZURE,
            "azure-openai-http-error-body/v1",
            "azure-openai-success-body/v1",
        ),
        (
            "aws_bedrock.rs",
            BEDROCK,
            "aws-bedrock-http-error-body/v1",
            "aws-bedrock-success-body/v1",
        ),
    ] {
        assert_no_unbounded_response_reads(name, source);
        let production = production(source);
        assert!(
            production.contains("response_bounds::decode_json("),
            "{name}: successful JSON must be read through the bounded decoder"
        );
        // Either form is a capped read; adapters that classify the envelope
        // (Azure policy errors, Bedrock `__type`) keep the text, the others
        // keep only the digest.
        let capped_error_reads = production
            .matches("response_bounds::error_body_evidence(")
            .count()
            + production
                .matches("response_bounds::error_body_with_evidence(")
                .count();
        assert_eq!(
            capped_error_reads, 2,
            "{name}: both the 429 quota path and the generic non-2xx path must \
             read a capped body"
        );
        assert!(production.contains("const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;"));
        assert!(production.contains(error_domain));
        assert!(production.contains(success_domain));
        // A whole-body key scrub is not a substitute for a digest: the endpoint
        // chooses the encoding it echoes. Azure is the one exception, and only
        // for the classified policy string that becomes visible refusal text —
        // it must not carry our own key, exactly as the OpenAI-compatible leaf
        // already guarantees.
        let allowed_key_scrubs = usize::from(name == "azure_openai.rs");
        assert_eq!(
            production.matches(".replace(self.api_key.expose()").count(),
            allowed_key_scrubs,
            "{name}: scrub the classified refusal string only, never the body"
        );
        assert!(
            !production.contains("Raw body:"),
            "{name}: a classified error must report guidance plus digest, never \
             the envelope bytes"
        );
    }
}

/// Copilot chat delegates to the bounded OpenAI-compatible transport; the one
/// envelope it reads itself is the short-lived token exchange.
#[test]
fn copilot_token_exchange_stays_bounded() {
    assert_no_unbounded_response_reads("copilot.rs", COPILOT);
    let production = production(COPILOT);
    assert!(production.contains("const MAX_TOKEN_BODY_BYTES: usize = 64 * 1024;"));
    assert!(production.contains("response_bounds::error_body_evidence("));
    assert!(production.contains("response_bounds::decode_json("));
    assert!(production.contains("copilot-token-error-body/v1"));
    assert!(production.contains("copilot-token-success-body/v1"));
}

/// Ratchet: adopting an adapter must also promote it out of `PENDING` and into
/// a real assertion block above, in the same change.
#[test]
fn pending_adapters_list_is_accurate() {
    assert!(
        !PENDING.is_empty(),
        "GOLD-R4-15k1 is closed only when every listed transport is bounded; \
         if this list is empty, close the roadmap item and delete this test"
    );
    for (name, source) in PENDING {
        assert!(
            !source.contains("response_bounds::"),
            "{name} now uses the shared bounded readers but is still listed as pending: \
             remove it from PENDING and add explicit assertions for it in this gate"
        );
    }
}
