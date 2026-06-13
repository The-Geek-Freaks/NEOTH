//! `neoth obsidian sync` — copy session-archive MD files into an Obsidian
//! vault. Phase 13 R-5 (CLI-first; GUI integration comes later).
//!
//! NEOTH already writes its session archive in an Obsidian-Periodic-Notes
//! compatible format (frontmatter + `## HH:MM:SS UTC` blocks). This
//! command performs the one-way copy into the operator's vault so the
//! conversations show up alongside the rest of their notes.
//!
//! Idempotent: target files that already exist with the same xxh3_64
//! content hash are skipped. Operator can re-run after every session
//! without churn.
//!
//! Out of scope here (deferred to Phase 13 follow-ups):
//!   - reverse-sync (operator-edited MD → archive)
//!   - Obsidian wikilink resolution (e.g. `[[2026-05-14]]`)
//!   - Dataview-compatible metadata enrichment

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::memory::archive;

#[derive(Args, Debug, Clone)]
pub struct ObsidianArgs {
    #[command(subcommand)]
    pub action: ObsidianAction,
    /// Override the NEOTH archive root (mostly for tests). Defaults to
    /// `~/.neoth/archive/`.
    #[arg(long, value_name = "DIR", global = true)]
    pub archive_root: Option<PathBuf>,
    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ObsidianAction {
    /// One-way copy: NEOTH archive → vault. Idempotent.
    Sync {
        /// Path to the operator's Obsidian vault root.
        vault: PathBuf,
        /// Subdirectory inside the vault for NEOTH sessions. Defaults to
        /// `NEOTH-sessions/`. Created on demand.
        #[arg(long, default_value = "NEOTH-sessions")]
        subdir: PathBuf,
        /// Print which files would be copied without writing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// List archive days that have at least one session MD file.
    Days,
    /// Scaffold a fresh NEOTH-Vault: creates the directory, drops a
    /// minimal `.obsidian/` config + a README, and pre-creates the
    /// `NEOTH-sessions/` subdir so `sync` lands without operator
    /// configuration. Safe to re-run — existing files are left alone.
    Init {
        /// Vault path to create. Defaults to `~/Documents/NEOTH-Vault/`
        /// on every platform (the path Obsidian itself uses by default
        /// when the operator clicks "Create new vault").
        #[arg(long, value_name = "PATH")]
        vault: Option<PathBuf>,
    },
    /// GOLD-FEAT-03 — render NEOTH's own `PLAN/` design corpus (SPECs, design
    /// docs, Chorus verdicts) into an interlinked Obsidian self-wiki under
    /// `vault/<subdir>/`. `--dry-run` lists the pages that would be written
    /// without touching the vault.
    WikiBuild {
        /// Obsidian vault root to write the wiki into.
        vault: PathBuf,
        /// Subdirectory inside the vault for the wiki. Created on demand.
        #[arg(long, default_value = "NEOTH-Wiki")]
        subdir: PathBuf,
        /// Directory holding the source design docs. Defaults to `PLAN`
        /// (run from the repo root); point it elsewhere if the docs moved.
        #[arg(long, default_value = "PLAN")]
        source_dir: PathBuf,
        /// List the pages that would be written without writing anything.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Clone, Debug, Default)]
pub struct SyncStats {
    pub considered: usize,
    pub copied: usize,
    pub skipped_identical: usize,
    pub skipped_dry_run: usize,
}

pub async fn run_obsidian(args: ObsidianArgs) -> Result<()> {
    let root = args
        .archive_root
        .clone()
        .unwrap_or_else(archive::default_archive_root);
    match args.action {
        ObsidianAction::Sync {
            vault,
            subdir,
            dry_run,
        } => {
            let stats = sync_archive(&root, &vault, &subdir, dry_run).await?;
            render_sync(stats, args.output);
        }
        ObsidianAction::Days => {
            let days = list_archive_days(&root)?;
            render_days(days, args.output);
        }
        ObsidianAction::Init { vault } => {
            let vault_path = vault.unwrap_or_else(default_vault_path);
            let outcome = scaffold_vault(&vault_path)?;
            render_init(outcome, args.output);
        }
        ObsidianAction::WikiBuild {
            vault,
            subdir,
            source_dir,
            dry_run,
        } => {
            let out_dir = vault.join(&subdir);
            let (stats, slugs) = crate::wiki::build_wiki(&source_dir, &out_dir, dry_run)?;
            render_wiki_build(&stats, &slugs, &out_dir, args.output);
        }
    }
    Ok(())
}

/// Render the `wiki-build` outcome — JSON dumps the stats; Table prints a
/// summary line + (on dry-run) the page list that *would* be written.
fn render_wiki_build(
    stats: &crate::wiki::WikiBuildStats,
    slugs: &[String],
    out_dir: &Path,
    output: crate::cli::OutputFormat,
) {
    use crate::cli::OutputFormat;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let v = serde_json::json!({
                "sources": stats.sources,
                "pages_planned": stats.pages_planned,
                "pages_written": stats.pages_written,
                "dry_run": stats.dry_run,
                "out_dir": out_dir.display().to_string(),
                "pages": slugs,
            });
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        }
        OutputFormat::Table => {
            let plural = |n: usize| if n == 1 { "page" } else { "pages" };
            if stats.dry_run {
                println!(
                    "[dry-run] {} source docs → {} {} would be written to {}",
                    stats.sources,
                    stats.pages_planned,
                    plural(stats.pages_planned),
                    out_dir.display()
                );
                for slug in slugs {
                    println!("    {slug}.md");
                }
            } else {
                println!(
                    "self-wiki: {} source docs → {} {} written to {}",
                    stats.sources,
                    stats.pages_written,
                    plural(stats.pages_written),
                    out_dir.display()
                );
            }
        }
    }
}

/// `~/Documents/NEOTH-Vault/` — same default Obsidian uses for new vaults
/// on every platform. Falls back to the current dir when HOME / USERPROFILE
/// can't be resolved (rare; mostly affects locked-down containers).
fn default_vault_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join("Documents").join("NEOTH-Vault")
}

#[derive(Clone, Debug, Default)]
pub struct InitOutcome {
    pub vault_path: PathBuf,
    /// True when the vault directory existed before we ran.
    pub vault_existed: bool,
    /// Files we wrote (relative to vault root). Pre-existing files
    /// with non-empty content are left alone, so this list is
    /// authoritative — operators see exactly what was created.
    pub created_files: Vec<PathBuf>,
    /// Files we kept untouched because they already had content.
    pub skipped_existing: Vec<PathBuf>,
}

/// Create the vault directory + drop the curated `.obsidian/` config
/// + a NEOTH README + the `NEOTH-sessions/` pre-created subdir. Safe
///   to re-run — only writes files that don't exist; existing files are
///   reported in `skipped_existing` and stay untouched.
fn scaffold_vault(vault: &Path) -> Result<InitOutcome> {
    let vault_existed = vault.exists();
    std::fs::create_dir_all(vault)
        .with_context(|| format!("create vault dir {}", vault.display()))?;
    std::fs::create_dir_all(vault.join(".obsidian")).context("create .obsidian dir")?;
    std::fs::create_dir_all(vault.join("NEOTH-sessions")).context("create NEOTH-sessions dir")?;

    let mut created = Vec::new();
    let mut skipped = Vec::new();

    // `.obsidian/app.json` — minimal: enable showLineNumber + spell-check
    // off (NEOTH session MDs contain code that triggers false positives).
    // Operators editing the vault later override these via the Obsidian
    // settings UI; we just give them a sensible default.
    write_if_absent(
        vault,
        Path::new(".obsidian/app.json"),
        APP_JSON,
        &mut created,
        &mut skipped,
    )?;
    // `.obsidian/appearance.json` — system theme; lets the OS pick
    // light/dark per the operator's session preference.
    write_if_absent(
        vault,
        Path::new(".obsidian/appearance.json"),
        APPEARANCE_JSON,
        &mut created,
        &mut skipped,
    )?;
    // `.obsidian/community-plugins.json` — empty array. We document
    // the recommended plugin list in the README rather than enabling
    // anything automatically; auto-plugin-install is O-3 (deferred).
    write_if_absent(
        vault,
        Path::new(".obsidian/community-plugins.json"),
        "[]\n",
        &mut created,
        &mut skipped,
    )?;
    // Operator-facing README that explains the vault layout + what
    // NEOTH writes into NEOTH-sessions/ + the recommended plugins.
    write_if_absent(
        vault,
        Path::new("README.md"),
        VAULT_README,
        &mut created,
        &mut skipped,
    )?;
    // Marker file Obsidian itself drops into vault roots — saves the
    // operator one "Open as vault" confirmation dialog when they first
    // launch Obsidian and point at this folder.
    write_if_absent(
        vault,
        Path::new(".obsidian/workspace.json"),
        WORKSPACE_JSON,
        &mut created,
        &mut skipped,
    )?;

    Ok(InitOutcome {
        vault_path: vault.to_path_buf(),
        vault_existed,
        created_files: created,
        skipped_existing: skipped,
    })
}

fn write_if_absent(
    vault: &Path,
    rel: &Path,
    body: &str,
    created: &mut Vec<PathBuf>,
    skipped: &mut Vec<PathBuf>,
) -> Result<()> {
    let target = vault.join(rel);
    if target.exists() {
        // Empty placeholder counts as "needs write" — covers the edge
        // case where a prior partial run left a 0-byte file behind.
        if std::fs::metadata(&target)
            .map(|m| m.len() > 0)
            .unwrap_or(false)
        {
            skipped.push(rel.to_path_buf());
            return Ok(());
        }
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create parent of {}", target.display()))?;
    }
    std::fs::write(&target, body).with_context(|| format!("write {}", target.display()))?;
    created.push(rel.to_path_buf());
    Ok(())
}

/// Minimal `.obsidian/app.json` — line numbers on, spell-check off.
const APP_JSON: &str = r#"{
  "showLineNumber": true,
  "spellcheck": false,
  "alwaysUpdateLinks": true
}
"#;

/// System theme. Obsidian picks light/dark from OS preference.
const APPEARANCE_JSON: &str = r#"{
  "theme": "system"
}
"#;

/// Empty workspace pin so Obsidian doesn't show the "Open as vault?"
/// confirmation on first launch.
const WORKSPACE_JSON: &str = r#"{
  "main": {
    "id": "neoth-root",
    "type": "split",
    "children": []
  },
  "left": null,
  "right": null,
  "active": "neoth-root"
}
"#;

const VAULT_README: &str = r#"# NEOTH-Vault

This vault is scaffolded by `neoth obsidian init`. NEOTH writes session
transcripts into `NEOTH-sessions/<YYYY-MM-DD>/<file>.md` whenever the
operator runs `neoth obsidian sync`. The vault is otherwise yours —
add notes, link sessions, and edit freely.

## Layout

```
.obsidian/                    # Obsidian config (theme, line numbers)
NEOTH-sessions/<day>/*.md     # Session transcripts NEOTH wrote
README.md                     # This file
```

## Recommended plugins

Install these from Community Plugins inside Obsidian:

- **Dataview** — query sessions by date, operator, or topic.
- **Periodic Notes** — open `NEOTH-sessions/<today>/` with one shortcut.
- **Templater** — drop a daily-note template referencing today's sessions.
- **Smart Connections** — semantic search over the session transcripts.

NEOTH does not auto-install these (O-3 deferred). The list above
gives you the curated set the rest of the operator workflows assume.

## Sync workflow

```
neoth obsidian sync ~/Documents/NEOTH-Vault
```

The command walks `~/.neoth/archive/sessions/` and copies anything new
into this vault. It's idempotent — running it twice in a row writes
nothing the second time.

## Reverse path

Editing files inside `NEOTH-sessions/` is safe but the changes are
not yet re-ingested into NEOTH's recall layer (O-5 deferred). Treat
your edits as the operator-readable layer; the source of truth lives
in `~/.neoth/archive/` until reverse-sync ships.
"#;

fn render_init(outcome: InitOutcome, output: OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let payload = serde_json::json!({
                "vault_path": outcome.vault_path,
                "vault_existed": outcome.vault_existed,
                "created_files": outcome.created_files,
                "skipped_existing": outcome.skipped_existing,
            });
            if let Ok(s) = serde_json::to_string_pretty(&payload) {
                println!("{s}");
            }
        }
        OutputFormat::Table => {
            println!(
                "# Vault {} at {}",
                if outcome.vault_existed {
                    "augmented"
                } else {
                    "created"
                },
                outcome.vault_path.display()
            );
            if !outcome.created_files.is_empty() {
                println!("  created:");
                for f in &outcome.created_files {
                    println!("    + {}", f.display());
                }
            }
            if !outcome.skipped_existing.is_empty() {
                println!("  kept (already had content):");
                for f in &outcome.skipped_existing {
                    println!("    = {}", f.display());
                }
            }
            println!();
            println!(
                "Next:  neoth obsidian sync {}",
                outcome.vault_path.display()
            );
        }
    }
}

/// Walk `archive_root/sessions/<YYYY-MM-DD>/*.md`, copy each into
/// `vault/<subdir>/<YYYY-MM-DD>/<filename>`. Files already present at the
/// destination with matching content hash are skipped.
///
/// `subdir` is treated as a simple name component — `..` or absolute
/// paths in the subdir would let a tampered freedom.yaml write outside
/// the configured vault. We reject those at the boundary so the rest
/// of the function can assume `dest_root` stays inside `vault`.
/// Reject path-traversal subdir values. Accepts EXACTLY one
/// `Component::Normal` value — anything else (absolute, parent-dir,
/// cur-dir mid-path, drive-relative `C:foo`, UNC, null byte) bails.
/// Operators who genuinely want nested vault paths build them as
/// separate join targets at the call site, not via this knob.
fn validate_subdir(subdir: &Path) -> Result<()> {
    // Reject null bytes outright — they don't appear in any legit
    // Unicode subdir and `Path::components` keeps them as part of a
    // `Normal` component which would survive validation.
    if let Some(s) = subdir.to_str() {
        if s.contains('\0') {
            anyhow::bail!("subdir contains a NUL byte");
        }
        // Windows drive-relative `C:foo` (no slash). `Path::is_absolute`
        // returns false for these. Detect any `:` in the string — no
        // legitimate subdir name uses a colon on either platform.
        if s.contains(':') {
            anyhow::bail!("subdir contains a `:` (drive-relative or UNC pattern rejected)");
        }
        // Backslash never appears in a legitimate cross-platform subdir.
        // On Unix, `PathBuf` keeps `\\server\share` as one Normal component,
        // so the multi-component check below misses UNC inputs. Reject `\`
        // outright to catch UNC + Windows separators on every host.
        if s.contains('\\') {
            anyhow::bail!("subdir contains a `\\` (UNC or Windows separator rejected)");
        }
    } else {
        anyhow::bail!("subdir is not valid UTF-8");
    }
    if subdir.is_absolute() {
        anyhow::bail!("subdir is absolute");
    }
    let comps: Vec<_> = subdir.components().collect();
    // Exactly one Normal component allowed. `./NEOTH` would render
    // as [CurDir, Normal("NEOTH")] — the previous tolerant version
    // accepted that, but a CurDir component anywhere lets craft
    // inputs that round-trip past validation while still resolving
    // up via subsequent join/canonicalize calls. Operators who want
    // `./NEOTH` write `NEOTH` instead.
    if comps.len() != 1 {
        anyhow::bail!(
            "subdir must be exactly one path component (got {})",
            comps.len()
        );
    }
    if !matches!(comps[0], std::path::Component::Normal(_)) {
        anyhow::bail!("subdir must be a Normal name component");
    }
    Ok(())
}

pub async fn sync_archive(
    archive_root: &Path,
    vault: &Path,
    subdir: &Path,
    dry_run: bool,
) -> Result<SyncStats> {
    validate_subdir(subdir).with_context(|| {
        format!(
            "invalid sync subdir {}: must be a simple name, not a traversal path",
            subdir.display()
        )
    })?;
    let sessions_root = archive_root.join("sessions");
    if !sessions_root.exists() {
        return Ok(SyncStats::default());
    }
    let mut stats = SyncStats::default();
    let dest_root = vault.join(subdir);
    if !dry_run {
        tokio::fs::create_dir_all(&dest_root)
            .await
            .with_context(|| format!("create vault subdir {}", dest_root.display()))?;
    }

    let mut day_rd = tokio::fs::read_dir(&sessions_root)
        .await
        .with_context(|| format!("read archive root {}", sessions_root.display()))?;
    while let Some(day_entry) = day_rd.next_entry().await? {
        if !day_entry.file_type().await?.is_dir() {
            continue;
        }
        let day_name = day_entry.file_name().to_string_lossy().into_owned();
        let day_dst = dest_root.join(&day_name);
        if !dry_run {
            tokio::fs::create_dir_all(&day_dst)
                .await
                .with_context(|| format!("create day dir {}", day_dst.display()))?;
        }

        let mut file_rd = tokio::fs::read_dir(day_entry.path()).await?;
        while let Some(file_entry) = file_rd.next_entry().await? {
            let path = file_entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("md") {
                continue;
            }
            stats.considered += 1;
            let dst = day_dst.join(path.file_name().unwrap());
            if !dry_run && is_identical(&path, &dst).await? {
                stats.skipped_identical += 1;
                continue;
            }
            if dry_run {
                stats.skipped_dry_run += 1;
                continue;
            }
            // Atomic copy: write to .tmp + rename so a partial copy
            // never leaves a torn file in the vault.
            let tmp = dst.with_extension("md.tmp");
            tokio::fs::copy(&path, &tmp)
                .await
                .with_context(|| format!("copy {} → {}", path.display(), tmp.display()))?;
            tokio::fs::rename(&tmp, &dst)
                .await
                .with_context(|| format!("rename {} → {}", tmp.display(), dst.display()))?;
            stats.copied += 1;
        }
    }
    Ok(stats)
}

async fn is_identical(src: &Path, dst: &Path) -> Result<bool> {
    if !dst.exists() {
        return Ok(false);
    }
    let src_bytes = tokio::fs::read(src).await?;
    let dst_bytes = tokio::fs::read(dst).await?;
    Ok(xxhash_rust::xxh3::xxh3_64(&src_bytes) == xxhash_rust::xxh3::xxh3_64(&dst_bytes))
}

pub fn list_archive_days(archive_root: &Path) -> Result<Vec<String>> {
    let sessions_root = archive_root.join("sessions");
    if !sessions_root.exists() {
        return Ok(Vec::new());
    }
    let mut days = Vec::new();
    for entry in std::fs::read_dir(&sessions_root)
        .with_context(|| format!("read {}", sessions_root.display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let name = entry.file_name().to_string_lossy().into_owned();
            days.push(name);
        }
    }
    days.sort();
    Ok(days)
}

fn render_sync(stats: SyncStats, output: OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let v = serde_json::json!({
                "considered": stats.considered,
                "copied": stats.copied,
                "skipped_identical": stats.skipped_identical,
                "skipped_dry_run": stats.skipped_dry_run,
            });
            println!("{v}");
        }
        OutputFormat::Table => {
            println!(
                "obsidian sync: {} considered, {} copied, {} unchanged, {} dry-run",
                stats.considered, stats.copied, stats.skipped_identical, stats.skipped_dry_run,
            );
        }
    }
}

fn render_days(days: Vec<String>, output: OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::json!({"days": days, "count": days.len()}));
        }
        OutputFormat::Table => {
            if days.is_empty() {
                println!("(no archived sessions yet)");
                return;
            }
            for d in &days {
                println!("{d}");
            }
            println!("# {} day(s)", days.len());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    async fn fake_archive(dir: &Path) -> PathBuf {
        let root = dir.join("archive");
        let sessions = root.join("sessions");
        for day in ["2026-05-13", "2026-05-14"] {
            let day_dir = sessions.join(day);
            tokio::fs::create_dir_all(&day_dir).await.unwrap();
            tokio::fs::write(
                day_dir.join("093412-abc.md"),
                format!("---\nsession: abc\nday: {day}\n---\n\nhello"),
            )
            .await
            .unwrap();
        }
        root
    }

    #[tokio::test]
    async fn sync_copies_every_md_into_vault_subdir() {
        let dir = tempdir().unwrap();
        let archive = fake_archive(dir.path()).await;
        let vault = dir.path().join("vault");
        let stats = sync_archive(&archive, &vault, &PathBuf::from("NEOTH-sessions"), false)
            .await
            .unwrap();
        assert_eq!(stats.considered, 2);
        assert_eq!(stats.copied, 2);
        assert_eq!(stats.skipped_identical, 0);
        assert!(
            vault
                .join("NEOTH-sessions/2026-05-13/093412-abc.md")
                .exists()
        );
        assert!(
            vault
                .join("NEOTH-sessions/2026-05-14/093412-abc.md")
                .exists()
        );
    }

    #[tokio::test]
    async fn sync_is_idempotent_on_second_run() {
        let dir = tempdir().unwrap();
        let archive = fake_archive(dir.path()).await;
        let vault = dir.path().join("vault");
        let subdir = PathBuf::from("NEOTH-sessions");
        let _ = sync_archive(&archive, &vault, &subdir, false)
            .await
            .unwrap();
        let stats = sync_archive(&archive, &vault, &subdir, false)
            .await
            .unwrap();
        assert_eq!(stats.considered, 2);
        assert_eq!(stats.copied, 0, "second run must skip identical files");
        assert_eq!(stats.skipped_identical, 2);
    }

    #[tokio::test]
    async fn sync_recopies_when_source_changes() {
        let dir = tempdir().unwrap();
        let archive = fake_archive(dir.path()).await;
        let vault = dir.path().join("vault");
        let subdir = PathBuf::from("NEOTH-sessions");
        sync_archive(&archive, &vault, &subdir, false)
            .await
            .unwrap();

        // Mutate one source file — second sync must re-copy it.
        let src = archive.join("sessions/2026-05-14/093412-abc.md");
        tokio::fs::write(&src, "---\nsession: abc\nday: 2026-05-14\n---\n\nrewritten")
            .await
            .unwrap();
        let stats = sync_archive(&archive, &vault, &subdir, false)
            .await
            .unwrap();
        assert_eq!(stats.copied, 1, "only the mutated file should re-copy");
        assert_eq!(stats.skipped_identical, 1);
    }

    #[tokio::test]
    async fn dry_run_writes_nothing() {
        let dir = tempdir().unwrap();
        let archive = fake_archive(dir.path()).await;
        let vault = dir.path().join("vault");
        let subdir = PathBuf::from("NEOTH-sessions");
        let stats = sync_archive(&archive, &vault, &subdir, true).await.unwrap();
        assert_eq!(stats.considered, 2);
        assert_eq!(stats.skipped_dry_run, 2);
        assert_eq!(stats.copied, 0);
        assert!(!vault.join("NEOTH-sessions").exists());
    }

    #[tokio::test]
    async fn sync_handles_missing_archive_root_cleanly() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault");
        let stats = sync_archive(
            &dir.path().join("nonexistent"),
            &vault,
            &PathBuf::from("x"),
            false,
        )
        .await
        .unwrap();
        assert_eq!(stats.considered, 0);
        assert_eq!(stats.copied, 0);
    }

    #[tokio::test]
    async fn list_days_returns_sorted_dirs() {
        let dir = tempdir().unwrap();
        let archive = fake_archive(dir.path()).await;
        let days = list_archive_days(&archive).unwrap();
        assert_eq!(
            days,
            vec!["2026-05-13".to_string(), "2026-05-14".to_string()]
        );
    }

    #[test]
    fn list_days_empty_archive() {
        let dir = tempdir().unwrap();
        let days = list_archive_days(dir.path()).unwrap();
        assert!(days.is_empty());
    }

    #[test]
    fn validate_subdir_accepts_simple_names() {
        validate_subdir(&PathBuf::from("NEOTH")).expect("plain name");
        validate_subdir(&PathBuf::from("NEOTH-2026")).expect("dashed");
        validate_subdir(&PathBuf::from("NEOTH_v2")).expect("underscore");
    }

    #[test]
    fn validate_subdir_rejects_cur_dir_prefix() {
        // Previous tolerant version accepted `./NEOTH`. New strict
        // version rejects to close a class of CurDir-mid-path
        // bypasses — operators write `NEOTH` instead.
        let r = validate_subdir(&PathBuf::from("./NEOTH"));
        assert!(r.is_err());
    }

    #[test]
    fn validate_subdir_rejects_parent_traversal() {
        let r = validate_subdir(&PathBuf::from("../escape"));
        assert!(r.is_err(), "`..` must not be a valid subdir");
    }

    #[test]
    fn validate_subdir_rejects_absolute() {
        let r = validate_subdir(&PathBuf::from("/etc"));
        assert!(r.is_err(), "absolute paths must be rejected");
    }

    #[test]
    fn validate_subdir_rejects_nested_components() {
        let r = validate_subdir(&PathBuf::from("a/b"));
        assert!(r.is_err(), "multi-component path must be rejected");
    }

    #[test]
    fn validate_subdir_rejects_drive_relative() {
        // Windows `C:evil` is not flagged by `is_absolute()` but
        // `vault.join("C:evil")` resolves outside the vault. Colon
        // check catches it.
        let r = validate_subdir(&PathBuf::from("C:evil"));
        assert!(r.is_err(), "drive-relative path must be rejected");
    }

    #[test]
    fn validate_subdir_rejects_unc_prefix() {
        // UNC `\\server\share` — `is_absolute()` catches this on
        // Windows, but the colon-free Linux PathBuf would still slip
        // through is_absolute. Our explicit multi-component check
        // handles both: more than one Normal component → reject.
        let p = PathBuf::from(r"\\server\share");
        let r = validate_subdir(&p);
        assert!(r.is_err());
    }

    #[test]
    fn validate_subdir_rejects_null_byte() {
        let r = validate_subdir(&PathBuf::from("name\0escape"));
        assert!(r.is_err(), "NUL bytes must be rejected");
    }

    #[tokio::test]
    async fn sync_rejects_traversal_subdir() {
        let dir = tempdir().unwrap();
        let archive = fake_archive(dir.path()).await;
        let vault = dir.path().join("vault");
        let err = sync_archive(&archive, &vault, &PathBuf::from("../escape"), false)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid sync subdir"),
            "expected traversal rejection, got: {err}"
        );
    }

    // ── O-2 vault scaffold tests ──────────────────────────────────────────

    #[test]
    fn scaffold_vault_creates_obsidian_dir_and_subdirs() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("NEOTH-Vault");
        let outcome = scaffold_vault(&vault).expect("scaffold");
        assert!(!outcome.vault_existed);
        assert!(vault.join(".obsidian").is_dir());
        assert!(vault.join("NEOTH-sessions").is_dir());
        // README + every config file must show up in `created_files`.
        let created: Vec<String> = outcome
            .created_files
            .iter()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .collect();
        assert!(created.contains(&"README.md".to_string()));
        assert!(created.contains(&".obsidian/app.json".to_string()));
        assert!(created.contains(&".obsidian/appearance.json".to_string()));
        assert!(created.contains(&".obsidian/community-plugins.json".to_string()));
        assert!(created.contains(&".obsidian/workspace.json".to_string()));
        assert!(outcome.skipped_existing.is_empty());
    }

    #[test]
    fn scaffold_vault_idempotent_on_rerun_with_existing_content() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault");
        // First pass: creates everything.
        scaffold_vault(&vault).unwrap();
        // Mutate README so we can verify it stays put.
        let custom = "# my own README — keep my edits";
        std::fs::write(vault.join("README.md"), custom).unwrap();
        // Second pass: README should land in `skipped_existing`,
        // body untouched.
        let outcome = scaffold_vault(&vault).unwrap();
        assert!(outcome.vault_existed);
        let skipped: Vec<String> = outcome
            .skipped_existing
            .iter()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .collect();
        assert!(
            skipped.contains(&"README.md".to_string()),
            "expected README in skipped, got skipped={skipped:?}"
        );
        let body = std::fs::read_to_string(vault.join("README.md")).unwrap();
        assert_eq!(body, custom);
    }

    #[test]
    fn scaffold_vault_rewrites_empty_placeholder_files() {
        // Edge case: a prior partial run left a 0-byte README behind.
        // scaffold_vault must rewrite it rather than treating it as
        // "operator-modified".
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        std::fs::write(vault.join("README.md"), "").unwrap();
        let outcome = scaffold_vault(&vault).unwrap();
        let created: Vec<String> = outcome
            .created_files
            .iter()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .collect();
        assert!(
            created.contains(&"README.md".to_string()),
            "expected empty README to be rewritten"
        );
        let body = std::fs::read_to_string(vault.join("README.md")).unwrap();
        assert!(body.contains("NEOTH-Vault"));
    }

    #[test]
    fn default_vault_path_resolves_to_documents_subdir() {
        let p = default_vault_path();
        let s = p.to_string_lossy();
        // Must always end with `NEOTH-Vault` regardless of OS.
        assert!(
            s.ends_with("NEOTH-Vault"),
            "default vault path must end with NEOTH-Vault: {s}"
        );
        // Documents/ component on every platform.
        assert!(
            s.contains("Documents"),
            "default vault path must route through Documents: {s}"
        );
    }
}
