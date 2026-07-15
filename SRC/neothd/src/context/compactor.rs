//! GOLD-ADAPT-ODY-06 — self-summary system prompt for the chat-path context
//! compactor (HARNESS-03).
//!
//! This module defines [`SELF_SUMMARY_SYSTEM_PROMPT`], the Rust port of the
//! Odysseus context-compactor self-summary persona. The prompt is passed as
//! the `system` field of the utility-provider summarisation request inside
//! [`crate::providers::compactor::CompactingProvider`].
//!
//! **Dependency direction**: this module is pure `&str` constants — it MUST NOT
//! import from `crate::providers` to avoid a circular dependency (providers →
//! context → providers).

/// System prompt sent to the utility provider when the compactor summarises
/// the "old zone" of the conversation history (ODY-06).
///
/// Design goals (ported from Odysseus `src/context_compactor.py`):
/// - Produce a **DENSE**, structured summary the operator can continue from.
/// - Retain all actionable information; drop chit-chat and superseded reasoning.
/// - Preserve code identifiers, file paths, error messages, URLs, and version
///   strings verbatim — these are high-entropy and cannot be reconstructed.
/// - State the current direction / next step explicitly so the reader can
///   orient without re-reading the raw history.
/// - Output ONLY the summary — no preamble, no "Here is a summary:", no
///   trailing commentary. The caller wraps it in `[CONTEXT SUMMARY: …]`.
pub const SELF_SUMMARY_SYSTEM_PROMPT: &str = "\
You are a conversation-history compactor operating inside NEOTH, an autonomous \
AI operator system. Your sole task is to reduce a long conversation history into \
a dense, structured summary that allows the conversation to continue seamlessly \
without loss of critical context.

RULES — follow exactly:
1. OUTPUT ONLY THE SUMMARY. Do not include any preamble, greeting, or phrase like \
\"Here is a summary\". Begin directly with the summary content.
2. PRESERVE VERBATIM: every file path, function or variable name, crate/package \
identifier, error message, URL, version string, WAL event ID, config key, or \
command-line flag that appeared in the conversation. These are irreplaceable.
3. STRUCTURE the summary with labelled sections when applicable:
   - **Tasks & Status** — list every task/item/ticket mentioned and its current \
status (open / done / blocked / deferred).
   - **Key Decisions** — decisions made, constraints adopted, approaches ruled out.
   - **Code & Files** — the specific files, functions, or data structures that are \
actively in scope, with their purpose.
   - **Errors & Fixes** — any error messages encountered and the fix applied or \
pending.
   - **Next Step** — the concrete action the conversation was about to take when \
this summary was triggered.
4. OMIT: pleasantries, repeated explanations, superseded plans, resolved \
side-conversations, and any information that has no bearing on continuing the work.
5. BE DENSE. Prefer bullet points and short sentences over prose paragraphs. \
Every sentence must carry information; remove filler.
6. If the history contains code snippets that are still relevant (not yet \
committed, or actively being debugged), include them inside fenced code blocks \
with the language tag.
7. Do not add opinions, suggestions, or new information not present in the \
history.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_contains_density_directive() {
        // The research plan specifies the prompt must contain "DENSE"
        assert!(
            SELF_SUMMARY_SYSTEM_PROMPT.contains("DENSE"),
            "SELF_SUMMARY_SYSTEM_PROMPT must contain the word DENSE (ODY-06 integration test requirement)"
        );
    }

    #[test]
    fn prompt_contains_no_preamble_rule() {
        // Ensure the prompt instructs the utility not to produce preamble
        assert!(
            SELF_SUMMARY_SYSTEM_PROMPT.contains("OUTPUT ONLY THE SUMMARY"),
            "prompt must instruct the utility to output only the summary"
        );
    }

    #[test]
    fn prompt_contains_next_step_section() {
        assert!(
            SELF_SUMMARY_SYSTEM_PROMPT.contains("Next Step"),
            "prompt must include a Next Step section"
        );
    }
}
