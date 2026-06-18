//! EM-04 (Session 24) — email draft generation + persistence.
//!
//! Produces operator-reviewable email drafts BEFORE any send
//! capability lands (EM-01 wires Gmail OAuth/IMAP for actual
//! delivery; EM-04 covers the compose half). The draft assembles:
//!
//!   - Salutation tuned to the recipient (formal "Sehr geehrte/r"
//!     for new addresses, casual "Hallo <Name>" for prior contacts).
//!   - The operator's brief, kept verbatim — NEOTH does NOT
//!     paraphrase the brief in MVP; that's a future LLM-rendering
//!     pass behind the wired provider in EM-01.
//!   - Per-snippet citation block when the operator passed grounded
//!     context (paperless consult hits, calendar hits, memory
//!     anchors) so the recipient sees WHY the operator's reply
//!     mentions the document.
//!   - Operator signature.
//!
//! ## Why no LLM in this layer
//!
//! EM-04's deliverable is the SHAPE — recipient discipline, citation
//! discipline, persistence + vault sync. The body-shaping pass is an
//! orthogonal concern that ships once EM-01's provider lands. Two
//! independent items keep the review surface small.
//!
//! ## Storage
//!
//! `~/.neoth/email_drafts/<id>.json` one-file-per-draft (parallel to
//! `proactive::action_staging::save_proposal` shape; operators
//! delete individual drafts without rewriting a log). Vault sync
//! to `<vault>/<subdir>/EmailDrafts/<id>.md` via atomic .tmp +
//! rename. Same allowlist on the draft id as PL-02 doc_id.

pub mod calendar;
pub mod draft;
pub mod gmail;
#[cfg(feature = "imap_fetch")]
pub mod imap_fetch;
pub mod inbound;
pub mod seen_store;
pub mod sender_policy;
pub mod threat_tiebreak;
