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

pub fn run_credential(args: CredentialArgs, output: OutputFormat) -> Result<()> {
    match args.action {
        CredentialAction::List => run_list(output),
        CredentialAction::Import { file } => run_import(&file, output),
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

fn run_import(file: &Path, output: OutputFormat) -> Result<()> {
    if !file.is_file() {
        anyhow::bail!("import file not found: {}", file.display());
    }
    let incoming = Credentials::load_or_default(file)
        .with_context(|| format!("parse import file {}", file.display()))?;
    let existing = Credentials::load().context("load existing credentials.yaml")?;
    let (merged, imported) = merge_credentials(&existing, &incoming)?;

    if imported.is_empty() {
        anyhow::bail!(
            "no credential fields found in {} — nothing to import (is it credentials.yaml-shaped?)",
            file.display()
        );
    }

    let dest = default_path();
    merged
        .write(&dest)
        .with_context(|| format!("write merged credentials to {}", dest.display()))?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({ "imported_keys": imported, "count": imported.len() })
        ),
        OutputFormat::Table => {
            println!("Imported {} credential key(s):", imported.len());
            for n in &imported {
                println!("  • {n}");
            }
            println!("(merged into {} — values hidden)", dest.display());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn merge_with_empty_incoming_changes_nothing() {
        let existing = creds("provider_key: P\n");
        let incoming = creds("{}");
        let (merged, imported) = merge_credentials(&existing, &incoming).unwrap();
        assert!(imported.is_empty());
        assert_eq!(set_key_names(&merged).unwrap(), vec!["provider_key"]);
    }
}
