//! `neoth credential {list, import}` — manage `~/.neoth/credentials.yaml`.
//!
//! - `list` prints which credential KEYS are currently set — **names only,
//!   never the secret values**.
//! - `import --file <path>` merges a credentials.yaml-shaped file into the
//!   canonical one: every SET field in the imported file overwrites the
//!   existing value; fields absent (or empty) in the import are left
//!   untouched. The merge is field-agnostic (serde mapping overlay) so new
//!   credential fields need no change here, and it NEVER prints secret values
//!   — only the names of the keys it imported.
//!
//! Credentials are stored plaintext in `credentials.yaml` by design (operators
//! who want them encrypted use OS-level disk encryption); this command reuses
//! [`Credentials::write`], which writes atomically at mode 0600 and zeroizes
//! the serialized buffer after the write.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::credentials::{Credentials, default_path};
use crate::config::keychain;

#[derive(Args, Debug, Clone)]
pub struct CredentialArgs {
    #[command(subcommand)]
    pub action: CredentialAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CredentialAction {
    /// List which credential keys are currently set. Prints KEY NAMES ONLY —
    /// never the secret values.
    List,
    /// Merge a credentials.yaml-shaped file into `~/.neoth/credentials.yaml`.
    /// Set fields in the imported file overwrite existing ones; absent/empty
    /// fields are left untouched. Never prints secret values.
    Import {
        /// Path to a YAML file with the same shape as `credentials.yaml`.
        #[arg(long)]
        file: PathBuf,
        /// Preview only: report which keys WOULD be added vs overwritten
        /// (names only, never values) and write nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Scan a file or directory for committed secrets (AWS / GitHub / OpenAI /
    /// Slack / Google keys, PEM private keys, `api_key = "…"` assignments).
    /// Findings REDACT the matched value. Exits non-zero when any secret is
    /// found (CI-friendly). Directories are walked recursively; `.git`,
    /// `target`, `node_modules`, dotdirs, binary + >2 MB files are skipped.
    Scan {
        /// File or directory to scan.
        path: PathBuf,
        /// Also flag long, high-entropy tokens that match no named pattern
        /// (catches generic/opaque secrets). Trades precision for recall.
        #[arg(long)]
        entropy: bool,
    },
    /// Migrate secrets between storage backends.
    ///
    /// `--to keychain` reads `~/.neoth/credentials.yaml`, writes every
    /// `SecretString` field into the OS credential store (Windows Credential
    /// Manager; macOS/Linux in follow-on commits), blanks those fields in the
    /// YAML, and updates `secrets_backend: keychain` in `freedom.yaml`.
    ///
    /// `--to file` reverses the migration: fetches secrets from the OS store,
    /// writes them back to `credentials.yaml`, deletes them from the store,
    /// and sets `secrets_backend: file` in `freedom.yaml`.
    ///
    /// Use `--dry-run` to preview what WOULD move without writing anything.
    Migrate {
        /// Target backend: `keychain` or `file`.
        #[arg(long)]
        to: String,
        /// Report what would change without writing anything.
        #[arg(long)]
        dry_run: bool,
    },
}

/// Sorted names of the credential fields that are currently set. Reads the
/// serialized mapping for KEY NAMES ONLY — the values (plaintext secrets) are
/// never returned, logged, or printed.
fn set_key_names(creds: &Credentials) -> Result<Vec<String>> {
    let value = serde_yaml::to_value(creds).context("inspect credentials")?;
    let mut names = Vec::new();
    if let Some(map) = value.as_mapping() {
        for (k, v) in map {
            if !v.is_null() {
                if let Some(name) = k.as_str() {
                    names.push(name.to_string());
                }
            }
        }
    }
    names.sort();
    Ok(names)
}

/// Overlay every SET (non-null) field of `incoming` onto `existing`,
/// field-agnostically (new credential fields need no change here). Returns the
/// merged credentials plus the sorted NAMES of the keys taken from `incoming`.
/// Values are never returned or logged.
fn merge_credentials(
    existing: &Credentials,
    incoming: &Credentials,
) -> Result<(Credentials, Vec<String>)> {
    let mut base = serde_yaml::to_value(existing).context("serialize existing credentials")?;
    let inc = serde_yaml::to_value(incoming).context("serialize incoming credentials")?;
    let mut imported = Vec::new();
    if let (Some(base_map), Some(inc_map)) = (base.as_mapping_mut(), inc.as_mapping()) {
        for (k, v) in inc_map {
            if !v.is_null() {
                base_map.insert(k.clone(), v.clone());
                if let Some(name) = k.as_str() {
                    imported.push(name.to_string());
                }
            }
        }
    }
    let merged: Credentials = serde_yaml::from_value(base).context("rebuild merged credentials")?;
    imported.sort();
    Ok((merged, imported))
}

/// Split `imported` keys into (added, overwritten) relative to the keys
/// already set in `existing`. Names only — values never touched. `added` =
/// keys not previously set; `overwritten` = keys that already had a value.
fn classify_import(existing: &[String], imported: &[String]) -> (Vec<String>, Vec<String>) {
    let mut added = Vec::new();
    let mut overwritten = Vec::new();
    for k in imported {
        if existing.iter().any(|e| e == k) {
            overwritten.push(k.clone());
        } else {
            added.push(k.clone());
        }
    }
    (added, overwritten)
}

pub fn run_credential(args: CredentialArgs, output: OutputFormat) -> Result<()> {
    match args.action {
        CredentialAction::List => run_list(output),
        CredentialAction::Import { file, dry_run } => run_import(&file, dry_run, output),
        CredentialAction::Scan { path, entropy } => run_scan(&path, entropy, output),
        CredentialAction::Migrate { to, dry_run } => run_migrate(&to, dry_run, output),
    }
}

/// Scan `path` (file or recursively-walked dir) for committed secrets, print a
/// redacted report, and return an error (non-zero exit) if anything was found.
fn run_scan(path: &std::path::Path, entropy: bool, output: OutputFormat) -> Result<()> {
    use crate::security::secrets_scan;
    let mut findings: Vec<(String, secrets_scan::Finding)> = Vec::new();
    let mut files_scanned = 0usize;
    scan_path(path, entropy, &mut findings, &mut files_scanned)
        .with_context(|| format!("scan {}", path.display()))?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<_> = findings
                .iter()
                .map(|(file, f)| {
                    serde_json::json!({
                        "file": file,
                        "line": f.line,
                        "pattern": f.pattern,
                        "redacted": f.redacted,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "files_scanned": files_scanned,
                    "findings": rows,
                    "count": findings.len(),
                })
            );
        }
        OutputFormat::Table => {
            if findings.is_empty() {
                println!("no secrets found ({files_scanned} files scanned)");
            } else {
                println!(
                    "⚠ {} secret(s) in {files_scanned} files scanned:",
                    findings.len()
                );
                for (file, f) in &findings {
                    println!("  {file}:{}  [{}]  {}", f.line, f.pattern, f.redacted);
                }
            }
        }
    }

    if findings.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(
            "{} secret(s) found across {files_scanned} scanned files",
            findings.len()
        )
    }
}

/// Recursively walk `path`, collecting findings. Skips symlinks, `.git`/
/// `target`/`node_modules`/dotdirs, and anything `scan_file` rejects.
fn scan_path(
    path: &std::path::Path,
    entropy: bool,
    out: &mut Vec<(String, crate::security::secrets_scan::Finding)>,
    files_scanned: &mut usize,
) -> Result<()> {
    let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if meta.is_file() {
        scan_file(path, entropy, out, files_scanned);
        return Ok(());
    }
    if !meta.is_dir() {
        return Ok(());
    }
    for de in std::fs::read_dir(path)?.flatten() {
        let p = de.path();
        let m = match de.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if m.file_type().is_symlink() {
            continue;
        }
        if m.is_dir() {
            let name = de.file_name().to_string_lossy().to_string();
            if matches!(name.as_str(), ".git" | "target" | "node_modules") || name.starts_with('.')
            {
                continue;
            }
            scan_path(&p, entropy, out, files_scanned)?;
        } else if m.is_file() {
            scan_file(&p, entropy, out, files_scanned);
        }
    }
    Ok(())
}

/// Scan one file: skip >2 MB + binary (NUL byte / non-UTF8), else run the
/// text scanner (+ the opt-in entropy pass) and tag each finding with the path.
fn scan_file(
    path: &std::path::Path,
    entropy: bool,
    out: &mut Vec<(String, crate::security::secrets_scan::Finding)>,
    files_scanned: &mut usize,
) {
    use crate::security::secrets_scan;
    const MAX_BYTES: u64 = 2 * 1024 * 1024;
    if std::fs::metadata(path).map(|m| m.len()).unwrap_or(0) > MAX_BYTES {
        return;
    }
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return,
    };
    if bytes.contains(&0) {
        return; // binary
    }
    let text = match std::str::from_utf8(&bytes) {
        Ok(t) => t,
        Err(_) => return,
    };
    *files_scanned += 1;
    let file = path.display().to_string();
    for f in secrets_scan::scan_text(text) {
        out.push((file.clone(), f));
    }
    if entropy {
        for f in secrets_scan::entropy_findings(
            text,
            secrets_scan::ENTROPY_MIN_LEN,
            secrets_scan::ENTROPY_MIN_BITS,
        ) {
            out.push((file.clone(), f));
        }
    }
}

fn run_list(output: OutputFormat) -> Result<()> {
    let creds = Credentials::load().context("load credentials.yaml")?;
    let names = set_key_names(&creds)?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({ "set_keys": names, "count": names.len() })
        ),
        OutputFormat::Table => {
            if names.is_empty() {
                println!("(no credentials configured)");
            } else {
                println!("Configured credential keys ({}):", names.len());
                for n in &names {
                    println!("  • {n}");
                }
                println!("(values hidden — names only)");
            }
        }
    }
    Ok(())
}

fn run_import(file: &Path, dry_run: bool, output: OutputFormat) -> Result<()> {
    if !file.is_file() {
        anyhow::bail!("import file not found: {}", file.display());
    }
    let incoming = Credentials::load_or_default(file)
        .with_context(|| format!("parse import file {}", file.display()))?;
    let existing = Credentials::load().context("load existing credentials.yaml")?;
    let existing_keys = set_key_names(&existing)?;
    let (merged, imported) = merge_credentials(&existing, &incoming)?;

    if imported.is_empty() {
        anyhow::bail!(
            "no credential fields found in {} — nothing to import (is it credentials.yaml-shaped?)",
            file.display()
        );
    }

    let (added, overwritten) = classify_import(&existing_keys, &imported);
    let dest = default_path();

    if !dry_run {
        merged
            .write(&dest)
            .with_context(|| format!("write merged credentials to {}", dest.display()))?;
    }

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "dry_run": dry_run,
                "imported_keys": imported,
                "added": added,
                "overwritten": overwritten,
                "count": imported.len(),
            })
        ),
        OutputFormat::Table => {
            let verb = if dry_run { "Would import" } else { "Imported" };
            println!("{verb} {} credential key(s):", imported.len());
            for n in &added {
                println!("  + {n}  (new)");
            }
            for n in &overwritten {
                println!("  ~ {n}  (overwrites existing)");
            }
            if dry_run {
                println!("(dry-run — nothing written; values hidden)");
            } else {
                println!("(merged into {} — values hidden)", dest.display());
            }
        }
    }
    Ok(())
}

/// Move secrets between `credentials.yaml` and the OS keychain.
///
/// `to` must be `"keychain"` or `"file"`. On success, `credentials.yaml` and
/// `freedom.yaml` are rewritten (unless `dry_run`). Prints a per-key summary.
fn run_migrate(to: &str, dry_run: bool, output: OutputFormat) -> Result<()> {
    let direction = match to {
        "keychain" => keychain::MigrationDirection::ToKeychain,
        "file" => keychain::MigrationDirection::ToFile,
        other => anyhow::bail!(
            "unknown migration target \"{other}\" — expected \"keychain\" or \"file\""
        ),
    };

    let cred_path = default_path();
    let creds = Credentials::load_or_default(&cred_path)
        .context("load credentials.yaml")?;

    let store = keychain::open_store()
        .context("open OS credential store — is the `keychain` feature compiled in?")?;

    let (updated_creds, report) = match direction {
        keychain::MigrationDirection::ToKeychain => {
            keychain::migrate_to_keychain(&creds, store.as_ref(), dry_run)
                .context("migrate secrets to keychain")?
        }
        keychain::MigrationDirection::ToFile => {
            keychain::migrate_to_file(&creds, store.as_ref(), dry_run)
                .context("migrate secrets to file")?
        }
    };

    // Print report FIRST so the operator sees failures before the bail.
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "dry_run": report.dry_run,
                    "direction": to,
                    "moved": report.moved,
                    "skipped": report.skipped,
                    "failed": report.failed
                        .iter()
                        .map(|(k, e)| serde_json::json!({"key": k, "error": e}))
                        .collect::<Vec<_>>(),
                    "is_clean": report.is_clean(),
                })
            );
        }
        OutputFormat::Table => {
            let verb = if dry_run { "Would move" } else { "Moved" };
            let backend_label = match direction {
                keychain::MigrationDirection::ToKeychain => store.backend_name(),
                keychain::MigrationDirection::ToFile => "credentials.yaml",
            };
            println!("{verb} {} secret(s) → {}:", report.moved.len(), backend_label);
            for k in &report.moved {
                println!("  + {k}");
            }
            if !report.skipped.is_empty() {
                println!("Skipped (not set): {}", report.skipped.join(", "));
            }
            if !report.failed.is_empty() {
                println!("FAILED:");
                for (k, e) in &report.failed {
                    println!("  ✗ {k}: {e}");
                }
            }
            if dry_run {
                println!("(dry-run — nothing written)");
            } else if !report.is_clean() {
                println!("(nothing written — fix the failures above and retry)");
            } else if !report.moved.is_empty() {
                println!(
                    "credentials.yaml and freedom.yaml updated. \
                     secrets_backend is now \"{to}\"."
                );
            }
        }
    }

    // Bail before any disk write if there were failures.
    // This keeps the error message truthful: "nothing written".
    if !report.is_clean() {
        anyhow::bail!(
            "{} migration failure(s) — nothing written; fix the failures above and retry",
            report.failed.len()
        );
    }

    // Persist updated credentials.yaml and freedom.yaml only when clean.
    if !dry_run && !report.moved.is_empty() {
        updated_creds
            .write(&cred_path)
            .with_context(|| format!("write updated credentials to {}", cred_path.display()))?;

        // Update secrets_backend in freedom.yaml — atomic write via temp+rename
        // so a crash mid-write cannot leave a half-written config file.
        let freedom_path = crate::config::FreedomConfig::default_path();
        if freedom_path.exists() {
            let body = std::fs::read_to_string(&freedom_path)
                .context("read freedom.yaml for backend update")?;
            let new_backend = match direction {
                keychain::MigrationDirection::ToKeychain => "keychain",
                keychain::MigrationDirection::ToFile => "file",
            };
            let updated = update_or_append_secrets_backend(&body, new_backend);
            atomic_write_str(&freedom_path, &updated)
                .context("write updated freedom.yaml")?;
        }
    }

    Ok(())
}

/// Write `content` to `path` atomically via a temp file in the same directory.
///
/// Creates a sibling temp file, writes the full content, then renames it over
/// the destination. On Windows, `fs::rename` over the same filesystem is
/// atomic at the OS level. A mid-write crash can only leave the temp file
/// behind (not a half-written `path`).
fn atomic_write_str(path: &std::path::Path, content: &str) -> anyhow::Result<()> {
    let parent = path.parent().unwrap_or(std::path::Path::new("."));
    let file_stem = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");
    let tmp = parent.join(format!(".~{}.{}.tmp", file_stem, std::process::id()));
    std::fs::write(&tmp, content.as_bytes())
        .with_context(|| format!("write temp file {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} → {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Replace or append `secrets_backend: <value>` in a freedom.yaml body.
///
/// Rules:
/// - Only the **first** matching line is replaced (a live key plus a commented
///   example line must not produce a duplicate key after the edit).
/// - A commented-out `# secrets_backend: …` line counts as a match and is
///   uncommented in place, so the example file comment becomes the live value.
/// - The file's original line-ending style (LF or CRLF) is preserved.
/// - Operates on raw byte positions to avoid split-and-rejoin artefacts.
fn update_or_append_secrets_backend(body: &str, value: &str) -> String {
    let needle = "secrets_backend:";
    let new_line = format!("secrets_backend: {value}");
    // Detect CRLF vs LF once so we can preserve the file's style when appending.
    let line_end = if body.contains("\r\n") { "\r\n" } else { "\n" };

    let mut replaced = false;
    let mut out = String::with_capacity(body.len() + new_line.len() + 4);
    let mut pos = 0;
    let bytes = body.as_bytes();

    while pos < bytes.len() {
        // Find the end of the current line (inclusive of its \n, if any).
        let eol_pos = bytes[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| pos + p + 1)   // include the \n
            .unwrap_or(bytes.len()); // no trailing newline on last line

        let raw_line = &body[pos..eol_pos];
        // Strip trailing \r\n / \n for matching (but write raw_line verbatim
        // unless we're replacing this line).
        let bare = raw_line.trim_end_matches('\n').trim_end_matches('\r');
        let canonical = bare.trim_start_matches('#').trim();

        if !replaced && canonical.starts_with(needle) {
            // Write the replacement value with the same line ending as the
            // original line so CRLF files stay CRLF.
            out.push_str(&new_line);
            if raw_line.ends_with("\r\n") {
                out.push_str("\r\n");
            } else if raw_line.ends_with('\n') {
                out.push('\n');
            }
            replaced = true;
        } else {
            out.push_str(raw_line);
        }
        pos = eol_pos;
    }

    if !replaced {
        // Append: ensure the file ends with a newline before our new line.
        if !out.ends_with('\n') {
            out.push_str(line_end);
        }
        out.push_str(&new_line);
        out.push_str(line_end);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_path_walks_dir_finds_secrets_skips_binary_and_skiplist_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("clean.txt"), "nothing to see here\n").unwrap();
        std::fs::write(root.join("leak.env"), "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n").unwrap();
        // binary file (NUL byte) — must be skipped even if it contains a match.
        std::fs::write(root.join("blob.bin"), b"AKIAIOSFODNN7EXAMPLE\x00\x01").unwrap();
        // a .git dir whose contents must NOT be scanned.
        std::fs::create_dir(root.join(".git")).unwrap();
        std::fs::write(
            root.join(".git").join("config"),
            "token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00\n",
        )
        .unwrap();

        let mut findings = Vec::new();
        let mut scanned = 0usize;
        scan_path(root, false, &mut findings, &mut scanned).unwrap();

        // Exactly the leak.env AWS key — not the binary blob, not the .git token.
        assert_eq!(findings.len(), 1, "only the one real text leak");
        assert!(findings[0].0.ends_with("leak.env"));
        assert_eq!(findings[0].1.pattern, "aws_access_key_id");
        assert!(!findings[0].1.redacted.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    /// Build a Credentials from partial YAML (avoids constructing SecretString
    /// by hand + exercises the same Deserialize path import uses).
    fn creds(yaml: &str) -> Credentials {
        serde_yaml::from_str(yaml).expect("valid credentials yaml")
    }

    #[test]
    fn set_key_names_lists_only_set_fields_sorted() {
        let c = creds("telegram_token: T\nprovider_key: P\n");
        let names = set_key_names(&c).unwrap();
        assert_eq!(names, vec!["provider_key", "telegram_token"]);
    }

    #[test]
    fn set_key_names_empty_when_nothing_set() {
        let c = creds("{}");
        assert!(set_key_names(&c).unwrap().is_empty());
    }

    #[test]
    fn merge_overwrites_set_fields_and_keeps_untouched_ones() {
        let existing = creds("provider_key: OLD\nslack_bot_token: KEEP\n");
        let incoming = creds("provider_key: NEW\ntelegram_token: TOK\n");
        let (merged, imported) = merge_credentials(&existing, &incoming).unwrap();
        // Imported names are exactly the incoming set fields, sorted.
        assert_eq!(imported, vec!["provider_key", "telegram_token"]);
        // Re-serialize to confirm the merge result (test-only inspection).
        let v = serde_yaml::to_value(&merged).unwrap();
        let m = v.as_mapping().unwrap();
        assert_eq!(m.get("provider_key").unwrap().as_str(), Some("NEW")); // overwritten
        assert_eq!(m.get("telegram_token").unwrap().as_str(), Some("TOK")); // added
        assert_eq!(m.get("slack_bot_token").unwrap().as_str(), Some("KEEP")); // untouched
    }

    #[test]
    fn classify_import_splits_added_vs_overwritten() {
        let existing = vec!["provider_key".to_string(), "slack_bot_token".to_string()];
        let imported = vec!["provider_key".to_string(), "telegram_token".to_string()];
        let (added, overwritten) = classify_import(&existing, &imported);
        assert_eq!(added, vec!["telegram_token"], "telegram is new");
        assert_eq!(
            overwritten,
            vec!["provider_key"],
            "provider_key already set"
        );
    }

    #[test]
    fn update_or_append_secrets_backend_replaces_existing_live_line() {
        let body = "operator_id: alex\nsecrets_backend: file\nlanguage_primary: de\n";
        let out = update_or_append_secrets_backend(body, "keychain");
        assert!(out.contains("secrets_backend: keychain"));
        assert!(!out.contains("secrets_backend: file"));
        // Other lines untouched.
        assert!(out.contains("operator_id: alex"));
    }

    #[test]
    fn update_or_append_secrets_backend_uncomments_commented_line() {
        let body = "operator_id: alex\n# secrets_backend: keychain   # default: file\n";
        let out = update_or_append_secrets_backend(body, "keychain");
        assert!(out.contains("secrets_backend: keychain"));
    }

    #[test]
    fn update_or_append_secrets_backend_appends_when_absent() {
        let body = "operator_id: alex\n";
        let out = update_or_append_secrets_backend(body, "keychain");
        assert!(out.ends_with("secrets_backend: keychain\n"));
        assert!(out.contains("operator_id: alex"));
    }

    #[test]
    fn update_or_append_secrets_backend_replaces_only_first_match() {
        // If both a live line and a commented example line are present, only
        // the first (live) line must be replaced — the commented one is left
        // as-is so there are no duplicate live keys in the file.
        let body = "secrets_backend: file\n# secrets_backend: keychain   # example\n";
        let out = update_or_append_secrets_backend(body, "keychain");
        // First line replaced.
        let mut lines = out.lines();
        assert_eq!(lines.next(), Some("secrets_backend: keychain"));
        // Second line (comment) left untouched.
        assert_eq!(
            lines.next(),
            Some("# secrets_backend: keychain   # example")
        );
        // No duplicate live key.
        let live_count = out
            .lines()
            .filter(|l| !l.trim_start().starts_with('#') && l.contains("secrets_backend:"))
            .count();
        assert_eq!(live_count, 1, "must have exactly one live secrets_backend key");
    }

    #[test]
    fn update_or_append_secrets_backend_preserves_crlf_line_endings() {
        let body = "operator_id: alex\r\nsecrets_backend: file\r\nlanguage_primary: de\r\n";
        let out = update_or_append_secrets_backend(body, "keychain");
        // Result must contain CRLF, not bare LF after the replaced line.
        assert!(
            out.contains("secrets_backend: keychain\r\n"),
            "replaced line must keep CRLF ending"
        );
        // Other lines must also be CRLF.
        assert!(out.contains("operator_id: alex\r\n"));
        // No stray bare LF as the only terminator (all \n preceded by \r).
        for (i, b) in out.as_bytes().iter().enumerate() {
            if *b == b'\n' {
                assert_eq!(
                    out.as_bytes().get(i.wrapping_sub(1)).copied(),
                    Some(b'\r'),
                    "bare LF at byte {i} in CRLF file"
                );
            }
        }
    }

    #[test]
    fn update_or_append_secrets_backend_appends_preserves_crlf() {
        let body = "operator_id: alex\r\n";
        let out = update_or_append_secrets_backend(body, "keychain");
        assert!(
            out.ends_with("secrets_backend: keychain\r\n"),
            "appended line must use CRLF style"
        );
    }

    #[test]
    fn merge_with_empty_incoming_changes_nothing() {
        let existing = creds("provider_key: P\n");
        let incoming = creds("{}");
        let (merged, imported) = merge_credentials(&existing, &incoming).unwrap();
        assert!(imported.is_empty());
        assert_eq!(set_key_names(&merged).unwrap(), vec!["provider_key"]);
    }
}
