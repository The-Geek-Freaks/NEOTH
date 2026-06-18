//! SC-01 — static guarantee that no plaintext secret VALUE is structurally
//! embedded in a WAL payload. WAL frames are the durable, exportable audit
//! ledger; a credential serialized into one would leak it to anyone the WAL is
//! shared with (`neoth wal export`, `wal show`, a transfer bundle).
//!
//! Walks every `.rs` under `src/wal/` and fails the build if a struct there
//! declares a field whose name is a known secret-bearing name (`password`,
//! `api_key`, `secret`, `bearer`, `access_token`, …). WAL payload structs must
//! carry only HASHES / metadata (the codebase contract — e.g. CHANNEL_INGRESS
//! stores `text_hash`, never the text). Today nothing matches; the guard
//! catches a future field addition that would turn the audit log into a secret
//! sink. Mirrors the `wal_emit_sites.rs` source-walk pattern.

use std::fs;
use std::path::{Path, PathBuf};

/// Field names that name a plaintext secret value. A WAL struct must never
/// carry one — only a hash/metadata of it.
const SECRET_FIELD_NAMES: &[&str] = &[
    "password",
    "passwd",
    "api_key",
    "apikey",
    "secret",
    "secret_key",
    "bearer",
    "bearer_token",
    "access_token",
    "refresh_token",
    "private_key",
    "client_secret",
];

/// `wal/<file>:<field>` exceptions. Empty by design.
const ALLOWED: &[&str] = &[];

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Pull the field name from a `    pub name: Type,` / `    name: Type,` line.
/// Returns `None` for non-field lines (comments, attributes, fn sigs, …).
fn field_name(line: &str) -> Option<&str> {
    let t = line.trim();
    if t.starts_with("//") || t.starts_with('#') || t.starts_with('*') {
        return None;
    }
    let t = t.strip_prefix("pub ").unwrap_or(t);
    let t = t.strip_prefix("pub(crate) ").unwrap_or(t);
    let (name, rest) = t.split_once(':')?;
    let name = name.trim();
    // A struct field name is a bare identifier; reject anything with spaces,
    // parens, `<`, etc. (so `fn foo(x: T)` / `match x:` don't false-match).
    if name.is_empty()
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        || name.chars().next().is_some_and(|c| c.is_ascii_digit())
    {
        return None;
    }
    // The type side must look like a type (rules out `let`/labels). Cheap check:
    // the rest is non-empty after trim.
    if rest.trim().is_empty() {
        return None;
    }
    Some(name)
}

#[test]
fn no_secret_named_fields_in_wal_structs() {
    let wal_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("wal");
    let mut files = Vec::new();
    collect_rs_files(&wal_root, &mut files);

    let mut offenders = Vec::new();
    for path in &files {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        let file = path.file_name().and_then(|s| s.to_str()).unwrap_or("?");
        for line in text.lines() {
            // Skip test modules' fixtures — only guard production payload types.
            if let Some(name) = field_name(line) {
                let lc = name.to_ascii_lowercase();
                if SECRET_FIELD_NAMES.contains(&lc.as_str()) {
                    let key = format!("{file}:{name}");
                    if !ALLOWED.contains(&key.as_str()) {
                        offenders.push(format!("{key}  (`{}`)", line.trim()));
                    }
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "SC-01: a WAL struct declares a plaintext-secret-named field — WAL payloads \
         are the exportable audit ledger and must carry only HASHES/metadata, never \
         a credential value:\n  {}\n  Store a hash (xxh3/SHA-256) instead, or — if \
         this genuinely is not a secret — add `<file>:<field>` to ALLOWED in \
         tests/no_plaintext_secrets_in_wal.rs with a justification.",
        offenders.join("\n  ")
    );
}

#[test]
fn allowlist_entries_are_well_formed() {
    // Hygiene: each ALLOWED entry must be `file.rs:field` so a stale entry is
    // visible. (Empty today.)
    for entry in ALLOWED {
        let (file, field) = entry.split_once(':').unwrap_or(("", ""));
        assert!(
            file.ends_with(".rs") && !field.is_empty(),
            "SC-01: malformed allowlist entry (expected `file.rs:field`): {entry}"
        );
    }
}
