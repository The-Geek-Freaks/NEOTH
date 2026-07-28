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
//! who want them encrypted use OS-level disk encryption); imports use the
//! cross-process-safe [`Credentials::update_at`] RMW boundary, preserve unknown
//! future fields, write atomically at mode 0600, and zeroize the serialized
//! buffer after publication.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize;

use crate::cli::OutputFormat;
use crate::config::credentials::{Credentials, default_path};
use crate::config::keychain::{self, SecretStore};
use crate::secret::SecretString;

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
    creds.configured_field_names()
}

/// Overlay every SET (non-null) field of `incoming` onto `existing`,
/// field-agnostically (new credential fields need no change here). Returns the
/// merged credentials plus the sorted NAMES of the keys taken from `incoming`.
/// Values are never returned or logged.
fn merge_credentials(
    existing: &Credentials,
    incoming: &Credentials,
) -> Result<(Credentials, Vec<String>)> {
    existing.merge_present_fields(incoming)
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

struct CredentialImportPlan {
    merged: Credentials,
    imported: Vec<String>,
    added: Vec<String>,
    overwritten: Vec<String>,
}

fn plan_import(
    existing: &Credentials,
    incoming: &Credentials,
    source: &Path,
) -> Result<CredentialImportPlan> {
    let existing_keys = set_key_names(existing)?;
    let (merged, imported) = merge_credentials(existing, incoming)?;
    if imported.is_empty() {
        anyhow::bail!(
            "no credential fields found in {} — nothing to import (is it credentials.yaml-shaped?)",
            source.display()
        );
    }
    let (added, overwritten) = classify_import(&existing_keys, &imported);
    Ok(CredentialImportPlan {
        merged,
        imported,
        added,
        overwritten,
    })
}

fn import_credentials_at(
    dest: &Path,
    incoming: &Credentials,
    source: &Path,
) -> Result<(Vec<String>, Vec<String>, Vec<String>)> {
    import_credentials_at_with_hook(dest, incoming, source, || {})
}

fn import_credentials_at_with_hook(
    dest: &Path,
    incoming: &Credentials,
    source: &Path,
    after_locked_load: impl FnOnce(),
) -> Result<(Vec<String>, Vec<String>, Vec<String>)> {
    Credentials::update_at(dest, |existing| {
        after_locked_load();
        let plan = plan_import(existing, incoming, source)?;
        *existing = plan.merged;
        Ok((plan.imported, plan.added, plan.overwritten))
    })
}

/// Parse an operator-supplied import as a standalone plaintext document.
///
/// Import files are not an instance home. Running the normal credential loader
/// against one would create a transaction lock beside the source and could even
/// recover an unrelated same-named journal in Downloads/removable media. The
/// import contract is deliberately plaintext; encrypted at-rest blobs remain
/// bound to the master key in their original NEOTH home.
fn load_external_import(path: &Path) -> Result<Credentials> {
    let raw = zeroize::Zeroizing::new(
        std::fs::read(path).with_context(|| format!("read import file {}", path.display()))?,
    );
    anyhow::ensure!(
        !crate::config::credentials::credentials_blob_is_encrypted(&raw),
        "{} is an encrypted NEOTH credential store, not a portable import; provide a plaintext credentials.yaml-shaped export",
        path.display()
    );
    let body = std::str::from_utf8(&raw)
        .with_context(|| format!("import file {} is not valid UTF-8", path.display()))?;
    // Collect names + nullness without retaining secret values in an ordinary
    // `serde_yaml::Value` heap tree. `IgnoredAny` consumes each non-null value.
    let raw_fields: std::collections::BTreeMap<String, Option<serde::de::IgnoredAny>> =
        serde_yaml::from_str(body)
            .with_context(|| format!("parse import field names at {}", path.display()))?;
    let incoming: Credentials = serde_yaml::from_str(body)
        .with_context(|| format!("parse import credentials YAML at {}", path.display()))?;

    // `Credentials` intentionally accepts unknown keys when loading the live
    // store so a newer binary's fields can survive an older binary's RMW. An
    // import is different: silently discarding an incoming future secret while
    // printing success is data loss. Reject every non-null key that did not
    // round-trip through this binary's typed schema. The sole legacy alias is
    // accepted explicitly and canonicalized by serde.
    let canonical = set_key_names(&incoming)?;
    let mut unknown = Vec::new();
    for (name, value) in raw_fields {
        if value.is_none() {
            continue;
        }
        let canonical_name = match name.as_str() {
            "pears_bearer_token" => "keet_bridge_bearer_token",
            other => other,
        };
        if !canonical.iter().any(|known| known == canonical_name) {
            unknown.push(name);
        }
    }
    unknown.sort();
    anyhow::ensure!(
        unknown.is_empty(),
        "import file {} contains credential field(s) this NEOTH build cannot preserve: {}; upgrade NEOTH before importing",
        path.display(),
        unknown.join(", ")
    );
    Ok(incoming)
}

struct KeychainMigrationEntry {
    key: String,
    previous: Option<SecretString>,
    intended: SecretString,
}

/// Capture the exact keychain state before a file -> keychain migration. This
/// snapshot remains necessary after `migrate_to_keychain` succeeds: a later
/// verification or pair-CAS failure must restore overwritten entries, not
/// merely delete the newly written names.
fn snapshot_keychain_migration(
    credentials: &Credentials,
    store: &dyn SecretStore,
) -> Result<Vec<KeychainMigrationEntry>> {
    let mut entries = Vec::new();
    for (field, intended) in keychain::secret_fields(credentials) {
        let previous = store
            .get(field)
            .with_context(|| format!("snapshot existing keychain value for {field}"))?;
        entries.push(KeychainMigrationEntry {
            key: field.to_string(),
            previous,
            intended: intended.clone(),
        });
    }
    if let Some(intended) = keychain::ssh_tunnels_secret(credentials)? {
        let field = "ssh_tunnels";
        let previous = store
            .get(field)
            .with_context(|| format!("snapshot existing keychain value for {field}"))?;
        entries.push(KeychainMigrationEntry {
            key: field.to_string(),
            previous,
            intended,
        });
    }
    Ok(entries)
}

fn restore_keychain_migration(
    store: &dyn SecretStore,
    entries: &[KeychainMigrationEntry],
    moved: &[String],
) -> Result<()> {
    let mut failures = Vec::new();
    for entry in entries
        .iter()
        .rev()
        .filter(|entry| moved.contains(&entry.key))
    {
        let restored = match entry.previous.as_ref() {
            Some(previous) => store.set(&entry.key, previous),
            None => store.delete(&entry.key),
        };
        if let Err(error) = restored {
            failures.push(format!("{}: {error}", entry.key));
        }
    }
    anyhow::ensure!(
        failures.is_empty(),
        "keychain rollback INCOMPLETE for {} entr(y/ies): {}",
        failures.len(),
        failures.join("; ")
    );
    Ok(())
}

fn verify_and_commit_keychain_migration_at(
    freedom_path: &Path,
    credentials_path: &Path,
    expected_fingerprint: [u8; 32],
    updated: &Credentials,
    store: &dyn SecretStore,
    entries: &[KeychainMigrationEntry],
    moved: &[String],
) -> Result<()> {
    verify_and_commit_keychain_migration_using(store, entries, moved, || {
        commit_migrated_credentials_at(
            freedom_path,
            credentials_path,
            expected_fingerprint,
            updated,
            keychain::MigrationDirection::ToKeychain,
        )
    })
}

fn verify_and_commit_keychain_migration_using<C>(
    store: &dyn SecretStore,
    entries: &[KeychainMigrationEntry],
    moved: &[String],
    commit: C,
) -> Result<()>
where
    C: FnOnce() -> Result<()>,
{
    let mut invalid = Vec::new();
    for entry in entries.iter().filter(|entry| moved.contains(&entry.key)) {
        match store.get(&entry.key) {
            Ok(Some(actual)) if actual.expose() == entry.intended.expose() => {}
            Ok(Some(_)) => invalid.push(format!("{} (value mismatch)", entry.key)),
            Ok(None) => invalid.push(format!("{} (missing)", entry.key)),
            Err(error) => invalid.push(format!("{} ({error})", entry.key)),
        }
    }
    if !invalid.is_empty() {
        if let Err(rollback) = restore_keychain_migration(store, entries, moved) {
            anyhow::bail!(
                "keychain verification failed for {} secret(s) ({}); {rollback:#}",
                invalid.len(),
                invalid.join(", ")
            );
        }
        anyhow::bail!(
            "keychain verification failed for {} secret(s) ({}); exact previous keychain values were restored and credentials.yaml is UNTOUCHED",
            invalid.len(),
            invalid.join(", ")
        );
    }

    if let Err(commit_error) = commit() {
        if crate::config::credentials::dual_file_target_publication_crossed(&commit_error) {
            return Err(commit_error).context(
                "file target publication crossed its recovery boundary; the new keychain generation was retained because credentials.yaml may already be cleared and freedom.yaml may already select the keychain; recover the PREPARED journal before retrying",
            );
        }
        if let Err(rollback) = restore_keychain_migration(store, entries, moved) {
            anyhow::bail!(
                "keychain values were written, but file/backend commit was refused ({commit_error:#}); {rollback:#}"
            );
        }
        return Err(commit_error).context(
            "file/backend commit was refused; exact previous keychain values were restored and credentials.yaml remains authoritative",
        );
    }
    Ok(())
}

fn known_credentials_fingerprint(credentials: &Credentials) -> Result<[u8; 32]> {
    let mut body = serde_yaml::to_string(credentials)
        .context("serialize known credentials for migration compare-and-swap")?;
    let digest = Sha256::digest(body.as_bytes()).into();
    body.zeroize();
    Ok(digest)
}

fn migrated_freedom_target(
    source: Option<&str>,
    direction: keychain::MigrationDirection,
) -> Result<Option<String>> {
    let backend = match direction {
        keychain::MigrationDirection::ToKeychain => "keychain",
        keychain::MigrationDirection::ToFile => "file",
    };
    Ok(match source {
        Some(source) => {
            let public = Credentials::public_freedom_without_legacy_ssh(source)?;
            Some(update_or_append_secrets_backend(&public, backend))
        }
        None => missing_freedom_backend_content(direction),
    })
}

fn commit_migrated_credentials_at(
    freedom_path: &Path,
    credentials_path: &Path,
    expected_fingerprint: [u8; 32],
    updated: &Credentials,
    direction: keychain::MigrationDirection,
) -> Result<()> {
    crate::config::credentials::Credentials::update_raw_freedom_with_credentials_at(
        freedom_path,
        credentials_path,
        |source, current| {
            anyhow::ensure!(
                known_credentials_fingerprint(current)? == expected_fingerprint,
                "credentials changed while the OS keychain migration was running; file/backend publication was not attempted — retry"
            );
            *current = updated.clone();
            Ok((migrated_freedom_target(source, direction)?, ()))
        },
    )
}

#[cfg(test)]
fn commit_migrated_credentials_at_with_fault(
    freedom_path: &Path,
    credentials_path: &Path,
    expected_fingerprint: [u8; 32],
    updated: &Credentials,
    direction: keychain::MigrationDirection,
    fault: crate::config::credentials::DualFileTestFaultPoint,
) -> Result<()> {
    crate::config::credentials::Credentials::test_update_raw_freedom_with_credentials_at_using_fault(
        freedom_path,
        credentials_path,
        |source, current| {
            anyhow::ensure!(
                known_credentials_fingerprint(current)? == expected_fingerprint,
                "credentials changed while the OS keychain migration was running; file/backend publication was not attempted — retry"
            );
            *current = updated.clone();
            Ok((migrated_freedom_target(source, direction)?, ()))
        },
        fault,
    )
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
    let incoming = load_external_import(file)?;
    let dest = default_path();
    let (imported, added, overwritten) = if dry_run {
        let existing = Credentials::load().context("load existing credentials.yaml")?;
        let plan = plan_import(&existing, &incoming, file)?;
        (plan.imported, plan.added, plan.overwritten)
    } else {
        import_credentials_at(&dest, &incoming, file)
            .with_context(|| format!("atomically merge credentials into {}", dest.display()))?
    };

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
fn print_migration_report(
    report: &keychain::MigrationReport,
    to: &str,
    output: OutputFormat,
    backend_name: &str,
    committed: bool,
) {
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
                    "committed": committed,
                })
            );
        }
        OutputFormat::Table => {
            let verb = if report.dry_run {
                "Would move"
            } else {
                "Moved"
            };
            println!(
                "{verb} {} secret(s) → {}:",
                report.moved.len(),
                backend_name
            );
            for key in &report.moved {
                println!("  + {key}");
            }
            if !report.skipped.is_empty() {
                println!("Skipped (not set): {}", report.skipped.join(", "));
            }
            if !report.failed.is_empty() {
                println!("FAILED:");
                for (key, error) in &report.failed {
                    println!("  ✗ {key}: {error}");
                }
            }
            if report.dry_run {
                println!("(dry-run — nothing written)");
            } else if !report.is_clean() {
                println!("(migration did not commit; inspect failures above)");
            } else if committed && !report.moved.is_empty() {
                println!(
                    "credentials.yaml and freedom.yaml committed together. \
                     secrets_backend is now \"{to}\"."
                );
            }
        }
    }
}

fn run_migrate(to: &str, dry_run: bool, output: OutputFormat) -> Result<()> {
    let direction = match to {
        "keychain" => keychain::MigrationDirection::ToKeychain,
        "file" => keychain::MigrationDirection::ToFile,
        other => anyhow::bail!(
            "unknown migration target \"{other}\" — expected \"keychain\" or \"file\""
        ),
    };

    let freedom_path = crate::config::FreedomConfig::default_path();
    crate::config::with_config_credential_migration_lock(&freedom_path, || {
        run_migrate_locked(to, direction, dry_run, output, &freedom_path)
    })
}

fn run_migrate_locked(
    to: &str,
    direction: keychain::MigrationDirection,
    dry_run: bool,
    output: OutputFormat,
    freedom_path: &Path,
) -> Result<()> {
    let cred_path = default_path();
    let store = keychain::open_store()
        .context("open OS credential store — is the `keychain` feature compiled in?")?;
    run_migrate_locked_with_store(
        to,
        direction,
        dry_run,
        output,
        freedom_path,
        &cred_path,
        store.as_ref(),
    )
    .map(|_| ())
}

fn run_migrate_locked_with_store(
    to: &str,
    direction: keychain::MigrationDirection,
    dry_run: bool,
    output: OutputFormat,
    freedom_path: &Path,
    cred_path: &Path,
    store: &dyn SecretStore,
) -> Result<keychain::MigrationReport> {
    // Preview the historical public SSH bundle in memory so it participates in
    // keychain SET/read-back without touching either file first. The final
    // PREPARED pair commit removes the public block and publishes the target
    // credential/backend image atomically; any pre-commit failure therefore
    // leaves the exact source files unchanged.
    let raw_creds = Credentials::load_or_default(cred_path).context("load credentials.yaml")?;
    let expected_fingerprint = known_credentials_fingerprint(&raw_creds)?;
    let (creds, legacy_ssh_present, _) =
        Credentials::load_with_legacy_ssh_preview_at(freedom_path, cred_path, store)
            .context("preview legacy SSH credential migration")?;

    // `migrate_to_keychain` rolls back failures during its own SET loop. Keep
    // this independent exact snapshot for failures after that loop (read-back
    // verification or the config/credential pair CAS).
    let keychain_before = if direction == keychain::MigrationDirection::ToKeychain && !dry_run {
        snapshot_keychain_migration(&creds, store)?
    } else {
        Vec::new()
    };

    let (updated_creds, mut report) = match direction {
        keychain::MigrationDirection::ToKeychain => {
            keychain::migrate_to_keychain(&creds, store, dry_run)
                .context("migrate secrets to keychain")?
        }
        keychain::MigrationDirection::ToFile => {
            keychain::migrate_to_file(&creds, store, dry_run).context("migrate secrets to file")?
        }
    };
    if legacy_ssh_present
        && direction == keychain::MigrationDirection::ToFile
        && !report.moved.iter().any(|field| field == "ssh_tunnels")
    {
        report.skipped.retain(|field| field != "ssh_tunnels");
        report.moved.push("ssh_tunnels".to_string());
    }

    let backend_label = match direction {
        keychain::MigrationDirection::ToKeychain => store.backend_name(),
        keychain::MigrationDirection::ToFile => "credentials.yaml",
    };

    // Bail before any disk write if there were failures.
    // This keeps the error message truthful: "nothing written".
    if !report.is_clean() {
        print_migration_report(&report, to, output, backend_label, false);
        anyhow::bail!(
            "{} migration failure(s) — no file/backend commit; inspect keychain rollback details above",
            report.failed.len()
        );
    }

    // Persist only when clean. Each direction is ordered so a crash at ANY step
    // leaves the secret reachable through the backend `freedom.yaml` currently
    // points at — never in a place the live read path won't consult.
    //
    // `--to file`:    write+verify file → switch backend → purge keychain.
    // `--to keychain`: verify keychain → switch backend → THEN blank file.
    //
    // The orderings are mirror images because the backend pointer must only be
    // flipped once the *new* source of truth is durable, and the *old* source is
    // only cleared once the pointer no longer references it.
    let commit_required = !report.moved.is_empty() || legacy_ssh_present;
    if !dry_run && commit_required {
        match direction {
            keychain::MigrationDirection::ToFile => {
                // Publish the populated file and backend pointer through one
                // PREPARED journal, but only if no known credential changed
                // while keychain reads were in flight. Unknown future fields
                // survive through the credential renderer's raw overlay.
                commit_migrated_credentials_at(
                    freedom_path,
                    cred_path,
                    expected_fingerprint,
                    &updated_creds,
                    direction,
                )
                .context("commit keychain-to-file migration")?;

                // VERIFY the committed file before deleting anything from the
                // keychain. A failure keeps the old keychain copy intact.
                let reloaded = Credentials::load_or_default(cred_path).context(
                    "re-load credentials.yaml to verify the migration before purging keychain",
                )?;
                let missing = reloaded.missing_migration_fields(&report.moved)?;
                if !missing.is_empty() {
                    anyhow::bail!(
                        "credentials.yaml was written but verification found {} secret(s) missing \
                         ({}); the keychain is left INTACT — no data lost. Re-run `neoth credential \
                         migrate --to file`.",
                        missing.len(),
                        missing
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }

                // freedom.yaml now reads from the verified file, so purge the
                // keychain. A delete failure here is a CLEANUP problem (the
                // secret is safe in the file, merely duplicated) — never loss.
                let cleanup_failed = keychain::purge_from_keychain(store, &report.moved);
                if !cleanup_failed.is_empty() {
                    eprintln!(
                        "WARNING: {} secret(s) are now in credentials.yaml but could NOT be removed \
                         from the OS keychain — they exist in BOTH places (no data was lost). \
                         Remove these keychain entries manually or re-run the migration:",
                        cleanup_failed.len()
                    );
                    for (k, e) in &cleanup_failed {
                        eprintln!("  ✗ {k}: {e}");
                    }
                    anyhow::bail!(
                        "keychain cleanup incomplete after a successful file migration — {} \
                         entr(y/ies) remain in the keychain (see warnings above)",
                        cleanup_failed.len()
                    );
                }
            }
            keychain::MigrationDirection::ToKeychain => {
                // Phase 1 SET every secret with rollback on partial failure.
                // Verify the exact intended values, then publish the blanked
                // file/backend pair. Any later failure restores overwritten and
                // previously-absent keychain entries exactly.
                verify_and_commit_keychain_migration_at(
                    freedom_path,
                    cred_path,
                    expected_fingerprint,
                    &updated_creds,
                    store,
                    &keychain_before,
                    &report.moved,
                )
                .context("finish file-to-keychain migration")?;
            }
        }
    }

    print_migration_report(
        &report,
        to,
        output,
        backend_label,
        !dry_run && commit_required,
    );
    Ok(report)
}

/// Content to CREATE for an absent `freedom.yaml`, or `None` when a missing file
/// needs no write for this direction. Pure so the fail-open fix is unit-testable
/// without writing to the real (hardcoded) config path.
///
/// `--to keychain` returns a minimal file — every `FreedomConfig` field is
/// `#[serde(default)]`, so only the backend pointer must be set. `--to file`
/// returns `None`: the runtime default is already `File`, so a missing file
/// already points at the right backend.
fn missing_freedom_backend_content(direction: keychain::MigrationDirection) -> Option<String> {
    match direction {
        keychain::MigrationDirection::ToKeychain => Some("secrets_backend: keychain\n".to_string()),
        keychain::MigrationDirection::ToFile => None,
    }
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
            .map(|p| pos + p + 1) // include the \n
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
        let skipped_token = format!("ghp_{}", "a".repeat(38));
        std::fs::write(
            root.join(".git").join("config"),
            format!("token={skipped_token}\n"),
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

    fn legacy_ssh_freedom_yaml() -> &'static str {
        r#"secrets_backend: file
future_extension:
  keep: true
ssh_tunnels:
  - endpoint:
      host: bastion.example
      username: alex
      auth:
        password: legacy-ssh-password
    remote_host: 127.0.0.1
    remote_port: 5432
"#
    }

    struct FailSshSetStore {
        inner: keychain::InMemorySecretStore,
    }

    impl SecretStore for FailSshSetStore {
        fn get(&self, key: &str) -> Result<Option<SecretString>> {
            self.inner.get(key)
        }

        fn set(&self, key: &str, value: &SecretString) -> Result<()> {
            if key == "ssh_tunnels" {
                anyhow::bail!("injected SSH keychain SET failure");
            }
            self.inner.set(key, value)
        }

        fn delete(&self, key: &str) -> Result<()> {
            self.inner.delete(key)
        }

        fn backend_name(&self) -> &'static str {
            "failing-memory"
        }
    }

    #[test]
    fn legacy_ssh_to_keychain_is_one_private_pair_commit() {
        let dir = tempfile::tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(&freedom_path, legacy_ssh_freedom_yaml()).unwrap();
        let store = keychain::InMemorySecretStore::default();

        crate::config::with_config_credential_migration_lock(&freedom_path, || {
            run_migrate_locked_with_store(
                "keychain",
                keychain::MigrationDirection::ToKeychain,
                false,
                OutputFormat::Json,
                &freedom_path,
                &credentials_path,
                &store,
            )
        })
        .unwrap();

        let public = std::fs::read_to_string(&freedom_path).unwrap();
        assert!(public.contains("secrets_backend: keychain"));
        assert!(public.contains("future_extension"));
        assert!(!public.contains("ssh_tunnels"));
        assert!(!public.contains("legacy-ssh-password"));
        assert!(
            Credentials::load_or_default(&credentials_path)
                .unwrap()
                .ssh_tunnels
                .is_none()
        );
        let mut effective = Credentials::default();
        keychain::supplement_from_store(&mut effective, &store).unwrap();
        let tunnels = effective.ssh_tunnels.expect("keychain SSH authority");
        match &tunnels[0].endpoint.auth {
            crate::transport::ssh_config::SshAuth::Password(secret) => {
                assert_eq!(secret.expose_secret(), "legacy-ssh-password");
            }
            other => panic!("unexpected migrated SSH auth: {other:?}"),
        }
    }

    #[test]
    fn legacy_ssh_to_file_commits_even_when_keychain_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(&freedom_path, legacy_ssh_freedom_yaml()).unwrap();
        let store = keychain::InMemorySecretStore::default();

        let report = crate::config::with_config_credential_migration_lock(&freedom_path, || {
            run_migrate_locked_with_store(
                "file",
                keychain::MigrationDirection::ToFile,
                false,
                OutputFormat::Json,
                &freedom_path,
                &credentials_path,
                &store,
            )
        })
        .unwrap();

        assert!(report.moved.iter().any(|field| field == "ssh_tunnels"));
        let public = std::fs::read_to_string(&freedom_path).unwrap();
        assert!(public.contains("secrets_backend: file"));
        assert!(public.contains("future_extension"));
        assert!(!public.contains("ssh_tunnels"));
        assert!(!public.contains("legacy-ssh-password"));
        let private = Credentials::load_or_default(&credentials_path).unwrap();
        let tunnels = private.ssh_tunnels.expect("file SSH authority");
        match &tunnels[0].endpoint.auth {
            crate::transport::ssh_config::SshAuth::Password(secret) => {
                assert_eq!(secret.expose_secret(), "legacy-ssh-password");
            }
            other => panic!("unexpected migrated SSH auth: {other:?}"),
        }
        assert!(store.get("ssh_tunnels").unwrap().is_none());
    }

    #[test]
    fn legacy_ssh_to_file_dry_run_plans_move_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let freedom_before = legacy_ssh_freedom_yaml().as_bytes().to_vec();
        let credentials_before = b"provider_key: file-provider-secret\n".to_vec();
        std::fs::write(&freedom_path, &freedom_before).unwrap();
        std::fs::write(&credentials_path, &credentials_before).unwrap();
        let store = keychain::InMemorySecretStore::default();

        let report = crate::config::with_config_credential_migration_lock(&freedom_path, || {
            run_migrate_locked_with_store(
                "file",
                keychain::MigrationDirection::ToFile,
                true,
                OutputFormat::Json,
                &freedom_path,
                &credentials_path,
                &store,
            )
        })
        .unwrap();

        assert!(report.dry_run);
        assert!(report.moved.iter().any(|field| field == "ssh_tunnels"));
        assert_eq!(std::fs::read(&freedom_path).unwrap(), freedom_before);
        assert_eq!(
            std::fs::read(&credentials_path).unwrap(),
            credentials_before
        );
        assert!(store.get("provider_key").unwrap().is_none());
        assert!(store.get("ssh_tunnels").unwrap().is_none());
        assert!(
            !dir.path()
                .join(".freedom-credentials.prepared.yaml")
                .exists()
        );
    }

    #[test]
    fn legacy_ssh_keychain_set_failure_restores_store_and_never_writes_files() {
        let dir = tempfile::tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        let freedom_before = legacy_ssh_freedom_yaml().as_bytes().to_vec();
        let credentials_before = b"provider_key: file-provider-secret\n".to_vec();
        std::fs::write(&freedom_path, &freedom_before).unwrap();
        std::fs::write(&credentials_path, &credentials_before).unwrap();
        let store = FailSshSetStore {
            inner: keychain::InMemorySecretStore::default(),
        };

        let error = crate::config::with_config_credential_migration_lock(&freedom_path, || {
            run_migrate_locked_with_store(
                "keychain",
                keychain::MigrationDirection::ToKeychain,
                false,
                OutputFormat::Json,
                &freedom_path,
                &credentials_path,
                &store,
            )
        })
        .unwrap_err();

        assert!(error.to_string().contains("migration failure"));
        assert_eq!(std::fs::read(&freedom_path).unwrap(), freedom_before);
        assert_eq!(
            std::fs::read(&credentials_path).unwrap(),
            credentials_before
        );
        assert!(store.get("provider_key").unwrap().is_none());
        assert!(store.get("ssh_tunnels").unwrap().is_none());
        assert!(
            !dir.path()
                .join(".freedom-credentials.prepared.yaml")
                .exists()
        );
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
    fn import_rmw_preserves_unknown_future_fields() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("credentials.yaml");
        let source = dir.path().join("import.yaml");
        std::fs::write(
            &dest,
            "provider_key: OLD\nfuture_secret: future-value-must-survive\n",
        )
        .unwrap();
        let incoming = creds("telegram_token: NEW-TOKEN\n");

        let (imported, added, overwritten) =
            import_credentials_at(&dest, &incoming, &source).unwrap();

        assert_eq!(imported, vec!["telegram_token"]);
        assert_eq!(added, vec!["telegram_token"]);
        assert!(overwritten.is_empty());
        let persisted: serde_yaml::Value =
            serde_yaml::from_slice(&std::fs::read(&dest).unwrap()).unwrap();
        assert_eq!(
            persisted["future_secret"].as_str(),
            Some("future-value-must-survive")
        );
        assert_eq!(persisted["provider_key"].as_str(), Some("OLD"));
        assert_eq!(persisted["telegram_token"].as_str(), Some("NEW-TOKEN"));
    }

    #[test]
    fn import_holds_rmw_lock_until_merged_publication() {
        use std::sync::mpsc;
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("credentials.yaml");
        let source = dir.path().join("import.yaml");
        std::fs::write(&dest, "provider_key: KEEP\n").unwrap();
        let incoming = creds("telegram_token: IMPORTED\n");
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let import_dest = dest.clone();
        let import_source = source.clone();
        let importer = std::thread::spawn(move || {
            import_credentials_at_with_hook(&import_dest, &incoming, &import_source, || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
            .unwrap()
        });

        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let writer_dest = dest.clone();
        let (writer_done_tx, writer_done_rx) = mpsc::channel();
        let writer = std::thread::spawn(move || {
            Credentials::update_at(&writer_dest, |credentials| {
                credentials.slack_bot_token = Some(crate::secret::SecretString::from("CONCURRENT"));
                Ok(())
            })
            .unwrap();
            writer_done_tx.send(()).unwrap();
        });
        assert!(
            writer_done_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err(),
            "a concurrent writer must remain blocked while import owns the RMW boundary"
        );

        release_tx.send(()).unwrap();
        let (imported, added, overwritten) = importer.join().unwrap();
        writer_done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        writer.join().unwrap();
        assert_eq!(imported, vec!["telegram_token"]);
        assert_eq!(added, vec!["telegram_token"]);
        assert!(overwritten.is_empty());

        let persisted = Credentials::load_or_default(&dest).unwrap();
        assert_eq!(persisted.provider_key.as_ref().unwrap().expose(), "KEEP");
        assert_eq!(
            persisted.telegram_token.as_ref().unwrap().expose(),
            "IMPORTED"
        );
        assert_eq!(
            persisted.slack_bot_token.as_ref().unwrap().expose(),
            "CONCURRENT"
        );
    }

    #[test]
    fn external_import_is_read_only_in_its_source_directory() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("portable-credentials.yaml");
        std::fs::write(&source, "provider_key: portable\n").unwrap();
        let mut permissions = std::fs::metadata(&source).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&source, permissions).unwrap();

        let imported = load_external_import(&source).unwrap();
        assert_eq!(imported.provider_key.as_ref().unwrap().expose(), "portable");
        assert!(
            !dir.path()
                .join(".freedom-credentials.transaction.lock")
                .exists(),
            "parsing an external import must not create an instance transaction lock"
        );
        assert!(
            !dir.path()
                .join(".freedom-credentials.prepared.yaml")
                .exists(),
            "parsing an external import must not recover or create an instance journal"
        );
    }

    #[test]
    fn external_import_rejects_unknown_future_secret_instead_of_claiming_success() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("newer-credentials.yaml");
        std::fs::write(
            &source,
            "provider_key: known\nfuture_provider_secret: must-not-disappear\n",
        )
        .unwrap();

        let error = load_external_import(&source).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("future_provider_secret"));
        assert!(message.contains("upgrade NEOTH"));
        assert!(
            !dir.path()
                .join(".freedom-credentials.transaction.lock")
                .exists()
        );
    }

    #[test]
    fn keychain_cas_refusal_restores_exact_previous_store_values() {
        let dir = tempfile::tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(&freedom_path, "secrets_backend: file\n").unwrap();
        std::fs::write(&credentials_path, "provider_key: authoritative-file\n").unwrap();

        let initial = Credentials::load_or_default(&credentials_path).unwrap();
        let expected = known_credentials_fingerprint(&initial).unwrap();
        let store = keychain::InMemorySecretStore::default();
        store
            .set("provider_key", &SecretString::from("preexisting-keychain"))
            .unwrap();
        let before = snapshot_keychain_migration(&initial, &store).unwrap();
        let (blanked, report) = keychain::migrate_to_keychain(&initial, &store, false).unwrap();
        assert!(report.is_clean());
        assert_eq!(
            store.get("provider_key").unwrap().unwrap().expose(),
            "authoritative-file"
        );

        Credentials::update_at(&credentials_path, |current| {
            current.slack_bot_token = Some(SecretString::from("concurrent-file-edit"));
            Ok(())
        })
        .unwrap();

        let error = verify_and_commit_keychain_migration_at(
            &freedom_path,
            &credentials_path,
            expected,
            &blanked,
            &store,
            &before,
            &report.moved,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("exact previous keychain values were restored"));
        assert_eq!(
            store.get("provider_key").unwrap().unwrap().expose(),
            "preexisting-keychain"
        );
        let freedom = std::fs::read_to_string(&freedom_path).unwrap();
        assert!(freedom.contains("secrets_backend: file"));
        let current = Credentials::load_or_default(&credentials_path).unwrap();
        assert_eq!(
            current.provider_key.as_ref().unwrap().expose(),
            "authoritative-file"
        );
        assert_eq!(
            current.slack_bot_token.as_ref().unwrap().expose(),
            "concurrent-file-edit"
        );
    }

    fn assert_keychain_migration_fault_boundary(
        fault: crate::config::credentials::DualFileTestFaultPoint,
        target_publication_crossed: bool,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(&freedom_path, "secrets_backend: file\n").unwrap();
        std::fs::write(&credentials_path, "provider_key: authoritative-file\n").unwrap();

        let initial = Credentials::load_or_default(&credentials_path).unwrap();
        let expected = known_credentials_fingerprint(&initial).unwrap();
        let store = keychain::InMemorySecretStore::default();
        store
            .set("provider_key", &SecretString::from("preexisting-keychain"))
            .unwrap();
        let before = snapshot_keychain_migration(&initial, &store).unwrap();
        let (blanked, report) = keychain::migrate_to_keychain(&initial, &store, false).unwrap();
        assert!(report.is_clean());

        let error =
            verify_and_commit_keychain_migration_using(&store, &before, &report.moved, || {
                commit_migrated_credentials_at_with_fault(
                    &freedom_path,
                    &credentials_path,
                    expected,
                    &blanked,
                    keychain::MigrationDirection::ToKeychain,
                    fault,
                )
            })
            .unwrap_err();
        assert_eq!(
            crate::config::credentials::dual_file_target_publication_crossed(&error),
            target_publication_crossed
        );
        let message = format!("{error:#}");
        if target_publication_crossed {
            assert!(message.contains("new keychain generation was retained"));
            assert_eq!(
                store.get("provider_key").unwrap().unwrap().expose(),
                "authoritative-file"
            );
        } else {
            assert!(message.contains("exact previous keychain values were restored"));
            assert_eq!(
                store.get("provider_key").unwrap().unwrap().expose(),
                "preexisting-keychain"
            );
        }

        let journal_path = dir.path().join(".freedom-credentials.prepared.yaml");
        assert!(
            journal_path.exists(),
            "the injected crash window must leave PREPARED for deterministic recovery"
        );
        let recovered = Credentials::load_or_default(&credentials_path).unwrap();
        assert!(
            !journal_path.exists(),
            "the next credential load must finish commit-or-rollback recovery"
        );

        let public = std::fs::read_to_string(&freedom_path).unwrap();
        if target_publication_crossed {
            assert!(public.contains("secrets_backend: keychain"));
            assert!(recovered.provider_key.is_none());
            let mut effective = recovered;
            keychain::supplement_from_store(&mut effective, &store).unwrap();
            assert_eq!(
                effective.provider_key.as_ref().unwrap().expose(),
                "authoritative-file"
            );
        } else {
            assert!(public.contains("secrets_backend: file"));
            assert_eq!(
                recovered.provider_key.as_ref().unwrap().expose(),
                "authoritative-file"
            );
        }
    }

    #[test]
    fn keychain_migration_rolls_back_before_file_target_publication() {
        assert_keychain_migration_fault_boundary(
            crate::config::credentials::DualFileTestFaultPoint::JournalPrepared,
            false,
        );
    }

    #[test]
    fn keychain_migration_retains_new_generation_after_freedom_publication() {
        assert_keychain_migration_fault_boundary(
            crate::config::credentials::DualFileTestFaultPoint::FreedomPublished,
            true,
        );
    }

    #[test]
    fn keychain_migration_retains_new_generation_after_final_directory_sync() {
        assert_keychain_migration_fault_boundary(
            crate::config::credentials::DualFileTestFaultPoint::DirectorySynced,
            true,
        );
    }

    #[test]
    fn migration_commit_rejects_stale_known_credentials_without_partial_pointer_flip() {
        let dir = tempfile::tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(
            &freedom_path,
            "secrets_backend: file\nfuture_config: keep-config\n",
        )
        .unwrap();
        std::fs::write(
            &credentials_path,
            "provider_key: authoritative-file-secret\nfuture_secret: keep-secret\n",
        )
        .unwrap();
        let initial = Credentials::load_or_default(&credentials_path).unwrap();
        let expected = known_credentials_fingerprint(&initial).unwrap();
        let mut blanked = initial.clone();
        blanked.provider_key = None;

        Credentials::update_at(&credentials_path, |credentials| {
            credentials.slack_bot_token =
                Some(crate::secret::SecretString::from("concurrent-known-update"));
            Ok(())
        })
        .unwrap();
        let error = commit_migrated_credentials_at(
            &freedom_path,
            &credentials_path,
            expected,
            &blanked,
            keychain::MigrationDirection::ToKeychain,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("credentials changed"));

        let config = std::fs::read_to_string(&freedom_path).unwrap();
        assert!(config.contains("secrets_backend: file"));
        assert!(config.contains("future_config: keep-config"));
        let current = Credentials::load_or_default(&credentials_path).unwrap();
        assert_eq!(
            current.provider_key.as_ref().unwrap().expose(),
            "authoritative-file-secret"
        );
        assert_eq!(
            current.slack_bot_token.as_ref().unwrap().expose(),
            "concurrent-known-update"
        );
        let raw = std::fs::read_to_string(&credentials_path).unwrap();
        assert!(raw.contains("future_secret: keep-secret"));
    }

    #[test]
    fn migration_commit_preserves_concurrent_unknown_fields() {
        let dir = tempfile::tempdir().unwrap();
        let freedom_path = dir.path().join("freedom.yaml");
        let credentials_path = dir.path().join("credentials.yaml");
        std::fs::write(&freedom_path, "secrets_backend: file\n").unwrap();
        std::fs::write(&credentials_path, "provider_key: move-me\n").unwrap();
        let initial = Credentials::load_or_default(&credentials_path).unwrap();
        let expected = known_credentials_fingerprint(&initial).unwrap();
        let mut blanked = initial;
        blanked.provider_key = None;
        std::fs::write(
            &credentials_path,
            "provider_key: move-me\nfuture_secret: concurrent-future-value\n",
        )
        .unwrap();

        commit_migrated_credentials_at(
            &freedom_path,
            &credentials_path,
            expected,
            &blanked,
            keychain::MigrationDirection::ToKeychain,
        )
        .unwrap();

        let config = std::fs::read_to_string(&freedom_path).unwrap();
        assert!(config.contains("secrets_backend: keychain"));
        let raw = std::fs::read_to_string(&credentials_path).unwrap();
        assert!(raw.contains("future_secret: concurrent-future-value"));
        assert!(!raw.contains("move-me"));
    }

    #[test]
    fn missing_freedom_to_keychain_creates_pointer_file() {
        // Fail-open fix: `migrate --to keychain` with no freedom.yaml must create
        // one pointing at the keychain backend, else neothd defaults to File and
        // reads the now-blanked credentials.yaml (silent secret loss).
        let c = missing_freedom_backend_content(keychain::MigrationDirection::ToKeychain)
            .expect("ToKeychain must create a pointer file");
        assert_eq!(c, "secrets_backend: keychain\n");
    }

    #[test]
    fn missing_freedom_to_file_is_noop() {
        // `--to file`: runtime default is already File, so a missing file already
        // points at the right backend — no write needed.
        assert!(
            missing_freedom_backend_content(keychain::MigrationDirection::ToFile).is_none(),
            "ToFile with missing freedom.yaml must stay a no-op"
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
        assert_eq!(
            live_count, 1,
            "must have exactly one live secrets_backend key"
        );
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
