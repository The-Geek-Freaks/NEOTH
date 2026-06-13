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
    let merged: Credentials =
        serde_yaml::from_value(base).context("rebuild merged credentials")?;
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
        CredentialAction::Scan { path } => run_scan(&path, output),
    }
}

/// Scan `path` (file or recursively-walked dir) for committed secrets, print a
/// redacted report, and return an error (non-zero exit) if anything was found.
fn run_scan(path: &std::path::Path, output: OutputFormat) -> Result<()> {
    use crate::security::secrets_scan;
    let mut findings: Vec<(String, secrets_scan::Finding)> = Vec::new();
    let mut files_scanned = 0usize;
    scan_path(path, &mut findings, &mut files_scanned)
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
                println!("⚠ {} secret(s) in {files_scanned} files scanned:", findings.len());
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
    out: &mut Vec<(String, crate::security::secrets_scan::Finding)>,
    files_scanned: &mut usize,
) -> Result<()> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?;
    if meta.is_file() {
        scan_file(path, out, files_scanned);
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
            if matches!(name.as_str(), ".git" | "target" | "node_modules") || name.starts_with('.') {
                continue;
            }
            scan_path(&p, out, files_scanned)?;
        } else if m.is_file() {
            scan_file(&p, out, files_scanned);
        }
    }
    Ok(())
}

/// Scan one file: skip >2 MB + binary (NUL byte / non-UTF8), else run the
/// text scanner and tag each finding with the file path.
fn scan_file(
    path: &std::path::Path,
    out: &mut Vec<(String, crate::security::secrets_scan::Finding)>,
    files_scanned: &mut usize,
) {
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
    for f in crate::security::secrets_scan::scan_text(text) {
        out.push((path.display().to_string(), f));
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
        std::fs::write(root.join(".git").join("config"), "token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00\n").unwrap();

        let mut findings = Vec::new();
        let mut scanned = 0usize;
        scan_path(root, &mut findings, &mut scanned).unwrap();

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
        assert_eq!(overwritten, vec!["provider_key"], "provider_key already set");
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
