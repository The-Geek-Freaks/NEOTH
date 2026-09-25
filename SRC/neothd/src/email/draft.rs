//! EM-04 draft module — see [`super`].

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::skills::store::{BoundDirectory, open_bound_directory, read_regular_file_bounded};

const MAX_DRAFT_BYTES: usize = 1024 * 1024;
const MAX_DRAFT_ENTRIES: usize = 4096;

/// One grounded snippet attached to a draft. Operators paste
/// paperless consult hits, calendar lookups, or memory anchors
/// here so the draft body cites real provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DraftContextSnippet {
    /// Short label the citation block renders (e.g. "Invoice
    /// doc-001.md", "Calendar 2026-05-30 14:00", "Memory
    /// 2026-05-25").
    pub source_label: String,
    /// Text the recipient sees as evidence. Trimmed by the renderer
    /// — operators paste freely.
    pub excerpt: String,
}

/// Locale/register for the salutation line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SalutationLocale {
    /// "Sehr geehrte/r <Name>," or "Hallo <Name>," (DE).
    GermanFormal,
    GermanCasual,
    /// "Dear <Name>," or "Hi <Name>," (EN).
    EnglishFormal,
    EnglishCasual,
}

impl SalutationLocale {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GermanFormal => "german_formal",
            Self::GermanCasual => "german_casual",
            Self::EnglishFormal => "english_formal",
            Self::EnglishCasual => "english_casual",
        }
    }

    /// Build the salutation line for a recipient. `display_name` is
    /// the human-readable name when known; empty → fallback per
    /// register ("Sehr geehrte Damen und Herren," / "Dear Sir or
    /// Madam,").
    pub fn salutation_for(self, display_name: &str) -> String {
        match (self, display_name.is_empty()) {
            (Self::GermanFormal, true) => "Sehr geehrte Damen und Herren,".to_string(),
            (Self::GermanFormal, false) => format!("Sehr geehrte/r {display_name},"),
            (Self::GermanCasual, true) => "Hallo,".to_string(),
            (Self::GermanCasual, false) => format!("Hallo {display_name},"),
            (Self::EnglishFormal, true) => "Dear Sir or Madam,".to_string(),
            (Self::EnglishFormal, false) => format!("Dear {display_name},"),
            (Self::EnglishCasual, true) => "Hi,".to_string(),
            (Self::EnglishCasual, false) => format!("Hi {display_name},"),
        }
    }

    /// Closing line for the same locale + register.
    pub fn closing(self) -> &'static str {
        match self {
            Self::GermanFormal => "Mit freundlichen Grüßen",
            Self::GermanCasual => "Viele Grüße",
            Self::EnglishFormal => "Sincerely,",
            Self::EnglishCasual => "Best,",
        }
    }
}

/// Status of one draft.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftStatus {
    /// Generated; operator has not yet reviewed.
    Pending,
    /// Operator opened the draft (vault `.md` was read or
    /// `neoth email show <id>` was run). Future filter for
    /// the proactive nudge so reminders skip already-seen drafts.
    Reviewed,
    /// Operator manually sent/copied the draft through their mail client and
    /// recorded that fact with `neoth email mark-sent <id>`. NEOTH has no
    /// SMTP/Gmail-API send path.
    Sent,
    /// Operator threw it away. Stays on disk so the audit shows
    /// what NEOTH proposed.
    Discarded,
}

impl DraftStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Reviewed => "reviewed",
            Self::Sent => "sent",
            Self::Discarded => "discarded",
        }
    }
}

/// One assembled draft email. Persisted as JSON; rendered as
/// markdown for the operator's vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailDraft {
    pub id: String,
    pub to: String,
    pub recipient_display_name: String,
    pub subject: String,
    /// Operator's brief, kept verbatim. The renderer treats it as
    /// the body's first paragraph — NEOTH does not paraphrase in
    /// MVP.
    pub brief: String,
    pub locale: SalutationLocale,
    pub signature: String,
    #[serde(default)]
    pub context_snippets: Vec<DraftContextSnippet>,
    pub generated_ts_unix: i64,
    pub status: DraftStatus,
    #[serde(default)]
    pub operator_note: String,
}

impl EmailDraft {
    /// Render the assembled email body — salutation + brief +
    /// citation block (when snippets present) + closing + signature.
    /// Plain text suitable for direct paste into any mail client.
    pub fn render_body(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push_str(&self.locale.salutation_for(&self.recipient_display_name));
        out.push_str("\n\n");
        out.push_str(self.brief.trim_end());
        out.push_str("\n\n");
        if !self.context_snippets.is_empty() {
            out.push_str("--- Referenzen ---\n");
            for s in &self.context_snippets {
                out.push_str(&format!("• {}: {}\n", s.source_label, s.excerpt.trim()));
            }
            out.push('\n');
        }
        out.push_str(self.locale.closing());
        out.push('\n');
        if !self.signature.is_empty() {
            out.push_str(self.signature.trim_end());
            out.push('\n');
        }
        out
    }

    /// Render the operator-facing Obsidian note. YAML frontmatter
    /// pins `to / subject / status / locale / id / generated_unix`
    /// for Dataview filters; body is the rendered email plus a
    /// commands footer.
    pub fn to_obsidian_md(&self) -> String {
        let body = self.render_body();
        format!(
            "---\n\
             id: \"{id}\"\n\
             to: \"{to}\"\n\
             subject: \"{subj}\"\n\
             status: \"{status}\"\n\
             locale: \"{locale}\"\n\
             generated_unix: {ts}\n\
             ---\n\n\
             # Email draft — {subj_h1}\n\n\
             **To:** {to_h}\n\n\
             ## Body\n\n\
             ```\n\
             {body}\
             ```\n\n\
             ## Operator action\n\n\
             - Reviewed: `neoth email review {id}`\n\
             - Sent: `neoth email mark-sent {id}`\n\
             - Discard: `neoth email discard {id}`\n",
            id = escape_yaml_string(&self.id),
            to = escape_yaml_string(&self.to),
            subj = escape_yaml_string(&self.subject),
            status = self.status.as_str(),
            locale = self.locale.as_str(),
            ts = self.generated_ts_unix,
            subj_h1 = self.subject,
            to_h = self.to,
            body = body,
        )
    }
}

fn escape_yaml_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Construct a stable, time-sortable draft id —
/// `<unix-secs>-<short-hash>`. Same format as
/// `proactive::action_staging::make_proposal_id` minus the kind
/// segment (drafts have no kind dimension).
pub fn make_draft_id(to: &str, subject: &str, generated_ts_unix: i64) -> String {
    let hash_input = format!("{to}|{subject}|{generated_ts_unix}");
    let hash = xxhash_rust::xxh3::xxh3_64(hash_input.as_bytes());
    format!("{}-{:08x}", generated_ts_unix, hash & 0xFFFF_FFFF)
}

/// Compose a draft from inputs. Pure — no I/O.
#[allow(clippy::too_many_arguments)]
pub fn build_draft(
    to: impl Into<String>,
    recipient_display_name: impl Into<String>,
    subject: impl Into<String>,
    brief: impl Into<String>,
    locale: SalutationLocale,
    signature: impl Into<String>,
    context_snippets: Vec<DraftContextSnippet>,
    generated_ts_unix: i64,
) -> EmailDraft {
    let to = to.into();
    let subject = subject.into();
    let id = make_draft_id(&to, &subject, generated_ts_unix);
    EmailDraft {
        id,
        to,
        recipient_display_name: recipient_display_name.into(),
        subject,
        brief: brief.into(),
        locale,
        signature: signature.into(),
        context_snippets,
        generated_ts_unix,
        status: DraftStatus::Pending,
        operator_note: String::new(),
    }
}

/// Convenience: current wall-clock unix seconds.
pub fn now_unix_seconds() -> i64 {
    crate::time::now_unix_i64()
}

/// Filesystem-safe id check — same rule as PL-02 doc_id.
fn is_safe_id(id: &str) -> bool {
    if id.is_empty() || id == "." || id == ".." {
        return false;
    }
    !id.chars()
        .any(|c| c == '/' || c == '\\' || c == '\0' || c.is_control())
}

/// Directory under `home` that holds per-draft JSON files.
pub fn drafts_dir(home: &Path) -> PathBuf {
    home.join("email_drafts")
}

/// Path to one draft's JSON file.
pub fn draft_path(home: &Path, id: &str) -> PathBuf {
    drafts_dir(home).join(format!("{id}.json"))
}

/// Persist a draft. Atomic .tmp + rename. Overwrites existing.
pub fn save_draft(home: &Path, draft: &EmailDraft) -> std::io::Result<PathBuf> {
    if !is_safe_id(&draft.id) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unsafe draft id {:?}", draft.id),
        ));
    }
    fs::create_dir_all(drafts_dir(home))?;
    let final_path = draft_path(home, &draft.id);
    let tmp_path = final_path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(draft).map_err(std::io::Error::other)?;
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        f.write_all(&body)?;
        f.flush()?;
    }
    if final_path.exists() {
        fs::remove_file(&final_path)?;
    }
    fs::rename(&tmp_path, &final_path)?;
    Ok(final_path)
}

pub fn load_draft(home: &Path, id: &str) -> Option<EmailDraft> {
    let body = fs::read_to_string(draft_path(home, id)).ok()?;
    serde_json::from_str(&body).ok()
}

fn anyhow_is_not_found(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|error| error.kind() == std::io::ErrorKind::NotFound)
}

fn anyhow_to_io(error: anyhow::Error) -> std::io::Error {
    let kind = error
        .chain()
        .find_map(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind)
        })
        .unwrap_or(std::io::ErrorKind::Other);
    std::io::Error::new(kind, error)
}

fn drafts_root(home: &Path) -> std::io::Result<Option<BoundDirectory>> {
    open_bound_directory(&drafts_dir(home), false, "email draft store").map_err(anyhow_to_io)
}

fn decode_draft(bytes: Vec<u8>, display_path: &Path) -> std::io::Result<EmailDraft> {
    let body = String::from_utf8(bytes).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "email draft {} is not UTF-8: {error}",
                display_path.display()
            ),
        )
    })?;
    serde_json::from_str(&body).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("parse email draft {}: {error}", display_path.display()),
        )
    })
}

/// List drafts using a bounded no-follow file-store walk. This stricter read
/// path is for external API consumers: a missing directory is empty, foreign
/// non-draft entries are ignored, and anything recognisably owned but unreadable
/// or malformed is surfaced rather than silently disappearing. Existing
/// [`list_drafts`] keeps its tolerant legacy behavior for its current callers.
pub fn list_drafts_checked(
    home: &Path,
    status_filter: Option<DraftStatus>,
) -> std::io::Result<Vec<EmailDraft>> {
    let Some(root) = drafts_root(home)? else {
        return Ok(Vec::new());
    };
    let entries = root.dir.entries()?;
    let mut out = Vec::new();
    let mut entry_count = 0usize;
    for entry in entries {
        let entry = entry?;
        entry_count = entry_count.checked_add(1).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "email draft entry counter overflow",
            )
        })?;
        if entry_count > MAX_DRAFT_ENTRIES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "email draft store {} exceeds the {MAX_DRAFT_ENTRIES}-entry limit",
                    root.display_path.display()
                ),
            ));
        }

        let name: OsString = entry.file_name();
        let Some(name_text) = name.to_str() else {
            tracing::warn!(store = %root.display_path.display(), "skipping non-UTF-8 foreign email draft entry");
            continue;
        };
        let Some(id) = name_text.strip_suffix(".json") else {
            continue;
        };
        if !is_safe_id(id) {
            tracing::warn!(store = %root.display_path.display(), "skipping foreign email draft filename");
            continue;
        }

        let display_path = root.display_path.join(&name);
        let bytes =
            match read_regular_file_bounded(&root.dir, &name, &display_path, MAX_DRAFT_BYTES) {
                Ok(bytes) => bytes,
                Err(error) if anyhow_is_not_found(&error) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!(
                            "email draft disappeared during checked read: {}",
                            display_path.display()
                        ),
                    ));
                }
                Err(error) => return Err(anyhow_to_io(error)),
            };
        let draft = decode_draft(bytes, &display_path)?;
        if draft.id != id {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "email draft filename id {id:?} does not match record id {:?} at {}",
                    draft.id,
                    display_path.display()
                ),
            ));
        }
        if status_filter
            .map(|status| draft.status == status)
            .unwrap_or(true)
        {
            out.push(draft);
        }
    }
    out.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(out)
}

/// List drafts. Optional status filter. Sorted ascending by id
/// (unix-seconds prefix → oldest first).
pub fn list_drafts(home: &Path, status_filter: Option<DraftStatus>) -> Vec<EmailDraft> {
    let dir = drafts_dir(home);
    let Ok(read) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out: Vec<EmailDraft> = read
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
        .filter_map(|e| fs::read_to_string(e.path()).ok())
        .filter_map(|b| serde_json::from_str::<EmailDraft>(&b).ok())
        .filter(|d| status_filter.map(|s| d.status == s).unwrap_or(true))
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

/// Flip status + write the operator note. Errors `NotFound` when
/// the id doesn't match a persisted draft.
pub fn set_draft_status(
    home: &Path,
    id: &str,
    new_status: DraftStatus,
    operator_note: &str,
) -> std::io::Result<EmailDraft> {
    let mut d = load_draft(home, id).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("draft {id} not found"),
        )
    })?;
    d.status = new_status;
    d.operator_note = operator_note.to_string();
    save_draft(home, &d)?;
    Ok(d)
}

/// Vault sync — render every drafted email matching `status_filter`
/// into `<vault>/<subdir>/EmailDrafts/<id>.md`. Per-file atomic
/// write. Same outcome shape as
/// `proactive::action_staging::ProposalSyncOutcome`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftSyncOutcome {
    pub written: usize,
    pub target_paths: Vec<PathBuf>,
}

pub fn sync_drafts_to_obsidian(
    neoth_home: &Path,
    vault_root: &Path,
    subdir: &str,
    status_filter: Option<DraftStatus>,
) -> std::io::Result<DraftSyncOutcome> {
    let drafts = list_drafts(neoth_home, status_filter);
    let dest_dir = vault_root.join(subdir).join("EmailDrafts");
    if drafts.is_empty() {
        return Ok(DraftSyncOutcome {
            written: 0,
            target_paths: Vec::new(),
        });
    }
    fs::create_dir_all(&dest_dir)?;

    let mut target_paths = Vec::with_capacity(drafts.len());
    for d in &drafts {
        let final_path = dest_dir.join(format!("{}.md", d.id));
        let tmp_path = final_path.with_extension("md.tmp");
        let body = d.to_obsidian_md();
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)?;
            f.write_all(body.as_bytes())?;
            f.flush()?;
        }
        if final_path.exists() {
            fs::remove_file(&final_path)?;
        }
        fs::rename(&tmp_path, &final_path)?;
        target_paths.push(final_path);
    }

    Ok(DraftSyncOutcome {
        written: drafts.len(),
        target_paths,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_draft(ts: i64) -> EmailDraft {
        build_draft(
            "vendor@example.com",
            "Sam Müller",
            "Re: Invoice #1234",
            "die Zahlung ist heute angewiesen. Danke für die Geduld.",
            SalutationLocale::GermanFormal,
            "Sam",
            vec![DraftContextSnippet {
                source_label: "Invoice doc-001.md".into(),
                excerpt: "Total due: 42.00 EUR — paid 2026-05-26".into(),
            }],
            ts,
        )
    }

    // ── enum surface ──────────────────────────────────────────────

    #[test]
    fn locale_as_str_pinned_for_audit() {
        assert_eq!(SalutationLocale::GermanFormal.as_str(), "german_formal");
        assert_eq!(SalutationLocale::GermanCasual.as_str(), "german_casual");
        assert_eq!(SalutationLocale::EnglishFormal.as_str(), "english_formal");
        assert_eq!(SalutationLocale::EnglishCasual.as_str(), "english_casual");
    }

    #[test]
    fn draft_status_as_str_pinned_for_audit() {
        assert_eq!(DraftStatus::Pending.as_str(), "pending");
        assert_eq!(DraftStatus::Reviewed.as_str(), "reviewed");
        assert_eq!(DraftStatus::Sent.as_str(), "sent");
        assert_eq!(DraftStatus::Discarded.as_str(), "discarded");
    }

    #[test]
    fn salutation_for_named_recipient_german_formal() {
        let s = SalutationLocale::GermanFormal.salutation_for("Sam Müller");
        assert_eq!(s, "Sehr geehrte/r Sam Müller,");
    }

    #[test]
    fn salutation_for_empty_recipient_falls_back_per_register() {
        assert_eq!(
            SalutationLocale::GermanFormal.salutation_for(""),
            "Sehr geehrte Damen und Herren,"
        );
        assert_eq!(SalutationLocale::GermanCasual.salutation_for(""), "Hallo,");
        assert_eq!(
            SalutationLocale::EnglishFormal.salutation_for(""),
            "Dear Sir or Madam,"
        );
        assert_eq!(SalutationLocale::EnglishCasual.salutation_for(""), "Hi,");
    }

    #[test]
    fn closing_per_locale_pinned() {
        assert_eq!(
            SalutationLocale::GermanFormal.closing(),
            "Mit freundlichen Grüßen"
        );
        assert_eq!(SalutationLocale::GermanCasual.closing(), "Viele Grüße");
        assert_eq!(SalutationLocale::EnglishFormal.closing(), "Sincerely,");
        assert_eq!(SalutationLocale::EnglishCasual.closing(), "Best,");
    }

    // ── id construction ───────────────────────────────────────────

    #[test]
    fn make_draft_id_deterministic_for_same_inputs() {
        let a = make_draft_id("a@b", "subj", 100);
        let b = make_draft_id("a@b", "subj", 100);
        assert_eq!(a, b);
    }

    #[test]
    fn make_draft_id_starts_with_unix_seconds() {
        let id = make_draft_id("a@b", "subj", 1_700_000_000);
        assert!(id.starts_with("1700000000-"));
    }

    #[test]
    fn make_draft_id_differs_on_to_or_subject() {
        let base = make_draft_id("a@b", "subj", 100);
        let alt_to = make_draft_id("c@d", "subj", 100);
        let alt_subj = make_draft_id("a@b", "other", 100);
        assert_ne!(base, alt_to);
        assert_ne!(base, alt_subj);
    }

    // ── render ────────────────────────────────────────────────────

    #[test]
    fn render_body_has_salutation_brief_references_closing_signature() {
        let d = sample_draft(100);
        let body = d.render_body();
        assert!(body.contains("Sehr geehrte/r Sam Müller,"));
        assert!(body.contains("die Zahlung ist heute angewiesen"));
        assert!(body.contains("--- Referenzen ---"));
        assert!(body.contains("Invoice doc-001.md"));
        assert!(body.contains("Mit freundlichen Grüßen"));
        assert!(body.ends_with("Sam\n"));
    }

    #[test]
    fn render_body_omits_references_block_when_no_snippets() {
        let mut d = sample_draft(100);
        d.context_snippets.clear();
        let body = d.render_body();
        assert!(!body.contains("--- Referenzen ---"));
    }

    #[test]
    fn to_obsidian_md_has_frontmatter_and_action_footer() {
        let d = sample_draft(1_700_000_000);
        let md = d.to_obsidian_md();
        assert!(md.starts_with("---\n"));
        assert!(md.contains(&format!("id: \"{}\"", d.id)));
        assert!(md.contains("to: \"vendor@example.com\""));
        assert!(md.contains("subject: \"Re: Invoice #1234\""));
        assert!(md.contains("status: \"pending\""));
        assert!(md.contains("locale: \"german_formal\""));
        assert!(md.contains("# Email draft —"));
        assert!(md.contains("**To:** vendor@example.com"));
        assert!(md.contains("```\n"));
        assert!(md.contains("neoth email mark-sent"));
    }

    #[test]
    fn to_obsidian_md_escapes_quotes_in_subject() {
        let d = build_draft(
            "a@b",
            "Name",
            r#"Subject with "quote""#,
            "body",
            SalutationLocale::EnglishCasual,
            "Sig",
            vec![],
            100,
        );
        let md = d.to_obsidian_md();
        assert!(
            md.contains(r#"subject: "Subject with \"quote\"""#),
            "got {md}",
        );
    }

    // ── persistence ───────────────────────────────────────────────

    #[test]
    fn save_load_roundtrip() {
        let home = tempfile::tempdir().unwrap();
        let d = sample_draft(100);
        save_draft(home.path(), &d).unwrap();
        let loaded = load_draft(home.path(), &d.id).unwrap();
        assert_eq!(loaded, d);
    }

    #[test]
    fn load_missing_returns_none() {
        let home = tempfile::tempdir().unwrap();
        assert!(load_draft(home.path(), "nope").is_none());
    }

    #[test]
    fn save_rejects_unsafe_id() {
        let home = tempfile::tempdir().unwrap();
        let mut d = sample_draft(100);
        d.id = "../escape".into();
        let err = save_draft(home.path(), &d).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn list_drafts_sorted_by_id_ascending() {
        let home = tempfile::tempdir().unwrap();
        let earlier = sample_draft(100);
        let later = sample_draft(200);
        save_draft(home.path(), &later).unwrap();
        save_draft(home.path(), &earlier).unwrap();
        let all = list_drafts(home.path(), None);
        assert_eq!(all.len(), 2);
        assert!(all[0].id < all[1].id);
    }

    #[test]
    fn list_drafts_status_filter() {
        let home = tempfile::tempdir().unwrap();
        let mut a = sample_draft(100);
        let mut b = sample_draft(200);
        a.status = DraftStatus::Pending;
        b.status = DraftStatus::Sent;
        save_draft(home.path(), &a).unwrap();
        save_draft(home.path(), &b).unwrap();
        let sent = list_drafts(home.path(), Some(DraftStatus::Sent));
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].id, b.id);
    }

    #[test]
    fn checked_list_drafts_filters_status_sorts_and_ignores_foreign_files() {
        let home = tempfile::tempdir().unwrap();
        let mut pending_earlier = sample_draft(100);
        let mut pending_later = sample_draft(400);
        let mut reviewed = sample_draft(200);
        let mut sent = sample_draft(300);
        let mut discarded = sample_draft(350);
        pending_earlier.status = DraftStatus::Pending;
        pending_later.status = DraftStatus::Pending;
        reviewed.status = DraftStatus::Reviewed;
        sent.status = DraftStatus::Sent;
        discarded.status = DraftStatus::Discarded;
        for draft in [
            &pending_later,
            &reviewed,
            &sent,
            &discarded,
            &pending_earlier,
        ] {
            save_draft(home.path(), draft).unwrap();
        }
        let drafts = drafts_dir(home.path());
        std::fs::write(drafts.join("editor-backup.txt"), b"foreign").unwrap();
        std::fs::write(drafts.join(".tmp"), b"foreign").unwrap();

        let pending = list_drafts_checked(home.path(), Some(DraftStatus::Pending)).unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].id, pending_earlier.id);
        assert_eq!(pending[1].id, pending_later.id);
    }

    #[test]
    fn checked_list_drafts_missing_store_is_empty_without_creation() {
        let home = tempfile::tempdir().unwrap();
        let drafts = drafts_dir(home.path());
        assert!(
            list_drafts_checked(home.path(), Some(DraftStatus::Pending))
                .unwrap()
                .is_empty()
        );
        assert!(!drafts.exists());
    }

    #[test]
    fn checked_list_drafts_recognised_corruption_is_an_error() {
        let home = tempfile::tempdir().unwrap();
        let draft = sample_draft(100);
        save_draft(home.path(), &draft).unwrap();
        std::fs::write(draft_path(home.path(), &draft.id), b"not json").unwrap();

        let error = list_drafts_checked(home.path(), Some(DraftStatus::Pending)).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn checked_list_drafts_rejects_oversized_recognised_record_without_mutation() {
        let home = tempfile::tempdir().unwrap();
        let draft = sample_draft(100);
        let path = draft_path(home.path(), &draft.id);
        std::fs::create_dir_all(drafts_dir(home.path())).unwrap();
        std::fs::File::create(&path)
            .unwrap()
            .set_len((MAX_DRAFT_BYTES + 1) as u64)
            .unwrap();
        let before_len = std::fs::metadata(&path).unwrap().len();

        let error = list_drafts_checked(home.path(), Some(DraftStatus::Pending)).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), before_len);
        assert!(path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn checked_list_drafts_refuses_recognised_symlinked_file_or_root() {
        use std::os::unix::fs::symlink;

        let outside = tempfile::tempdir().unwrap();
        let draft = sample_draft(100);
        save_draft(outside.path(), &draft).unwrap();
        let outside_path = draft_path(outside.path(), &draft.id);
        let outside_before = std::fs::read(&outside_path).unwrap();

        let file_link_home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(drafts_dir(file_link_home.path())).unwrap();
        symlink(&outside_path, draft_path(file_link_home.path(), &draft.id)).unwrap();
        assert!(list_drafts_checked(file_link_home.path(), None).is_err());
        assert_eq!(std::fs::read(&outside_path).unwrap(), outside_before);

        let root_link_home = tempfile::tempdir().unwrap();
        symlink(
            drafts_dir(outside.path()),
            drafts_dir(root_link_home.path()),
        )
        .unwrap();
        assert!(list_drafts_checked(root_link_home.path(), None).is_err());
        assert_eq!(std::fs::read(&outside_path).unwrap(), outside_before);
    }

    #[test]
    fn checked_list_drafts_rejects_filename_id_mismatch() {
        let home = tempfile::tempdir().unwrap();
        let draft = sample_draft(100);
        let mismatched_name = "200-00000000";
        let body = serde_json::to_vec(&draft).unwrap();
        std::fs::create_dir_all(drafts_dir(home.path())).unwrap();
        std::fs::write(draft_path(home.path(), mismatched_name), body).unwrap();

        let error = list_drafts_checked(home.path(), Some(DraftStatus::Pending)).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn set_draft_status_flips_persists() {
        let home = tempfile::tempdir().unwrap();
        let d = sample_draft(100);
        save_draft(home.path(), &d).unwrap();
        let updated =
            set_draft_status(home.path(), &d.id, DraftStatus::Sent, "delivered manually").unwrap();
        assert_eq!(updated.status, DraftStatus::Sent);
        assert_eq!(updated.operator_note, "delivered manually");
        let again = load_draft(home.path(), &d.id).unwrap();
        assert_eq!(again.status, DraftStatus::Sent);
    }

    #[test]
    fn set_draft_status_missing_id_not_found() {
        let home = tempfile::tempdir().unwrap();
        let err = set_draft_status(home.path(), "nope", DraftStatus::Sent, "").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    // ── vault sync ────────────────────────────────────────────────

    #[test]
    fn sync_empty_writes_nothing() {
        let home = tempfile::tempdir().unwrap();
        let vault = tempfile::tempdir().unwrap();
        let out = sync_drafts_to_obsidian(
            home.path(),
            vault.path(),
            "NEOTH",
            Some(DraftStatus::Pending),
        )
        .unwrap();
        assert_eq!(out.written, 0);
        assert!(out.target_paths.is_empty());
    }

    #[test]
    fn sync_writes_one_md_per_draft() {
        let home = tempfile::tempdir().unwrap();
        let vault = tempfile::tempdir().unwrap();
        save_draft(home.path(), &sample_draft(100)).unwrap();
        save_draft(home.path(), &sample_draft(200)).unwrap();

        let out = sync_drafts_to_obsidian(
            home.path(),
            vault.path(),
            "NEOTH",
            Some(DraftStatus::Pending),
        )
        .unwrap();
        assert_eq!(out.written, 2);
        for path in &out.target_paths {
            assert!(path.exists());
            let body = std::fs::read_to_string(path).unwrap();
            assert!(body.contains("# Email draft"));
        }
    }

    #[test]
    fn sync_filter_skips_non_matching_status() {
        let home = tempfile::tempdir().unwrap();
        let vault = tempfile::tempdir().unwrap();
        let mut sent = sample_draft(100);
        sent.status = DraftStatus::Sent;
        let pending = sample_draft(200);
        save_draft(home.path(), &sent).unwrap();
        save_draft(home.path(), &pending).unwrap();
        let out = sync_drafts_to_obsidian(
            home.path(),
            vault.path(),
            "NEOTH",
            Some(DraftStatus::Pending),
        )
        .unwrap();
        assert_eq!(out.written, 1);
    }

    #[test]
    fn sync_no_tmp_file_lingers() {
        let home = tempfile::tempdir().unwrap();
        let vault = tempfile::tempdir().unwrap();
        save_draft(home.path(), &sample_draft(100)).unwrap();
        sync_drafts_to_obsidian(home.path(), vault.path(), "NEOTH", None).unwrap();
        let dest_dir = vault.path().join("NEOTH").join("EmailDrafts");
        let any_tmp = std::fs::read_dir(&dest_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.path().extension().and_then(|x| x.to_str()) == Some("tmp"));
        assert!(!any_tmp, "tmp file leaked in {dest_dir:?}");
    }

    // ── snippet rendering ─────────────────────────────────────────

    #[test]
    fn body_renders_multiple_snippets_each_on_own_line() {
        let d = build_draft(
            "a@b",
            "Name",
            "subj",
            "brief",
            SalutationLocale::GermanCasual,
            "Sig",
            vec![
                DraftContextSnippet {
                    source_label: "Inv-1".into(),
                    excerpt: "first".into(),
                },
                DraftContextSnippet {
                    source_label: "Cal-2".into(),
                    excerpt: "second".into(),
                },
            ],
            100,
        );
        let body = d.render_body();
        assert!(body.contains("• Inv-1: first"));
        assert!(body.contains("• Cal-2: second"));
    }

    #[test]
    fn snippet_excerpt_trimmed_in_render() {
        let d = build_draft(
            "a@b",
            "Name",
            "subj",
            "brief",
            SalutationLocale::EnglishCasual,
            "Sig",
            vec![DraftContextSnippet {
                source_label: "x".into(),
                excerpt: "  padded  ".into(),
            }],
            100,
        );
        let body = d.render_body();
        assert!(body.contains("• x: padded"));
    }

    #[test]
    fn json_status_and_locale_snake_case() {
        let d = sample_draft(100);
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("\"status\":\"pending\""));
        assert!(json.contains("\"locale\":\"german_formal\""));
    }
}
