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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use crate::cli::OutputFormat;
use crate::cli::obsidian_sync_util::{DirMtimeCache, WriteCoalescer, detect_sync_conflicts};
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
    /// Report the Obsidian integration config from `freedom.yaml`. Pure read,
    /// no side effects. Shows whether a vault is configured and the key
    /// automation settings (auto-sync, wiki-rebuild, vault-reader).
    Status,
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
        /// GOLD-FEAT-03 slice 2 — after writing, push one recall-friendly
        /// pointer per doc into ground-truth (`idx_groundtruth`, scope
        /// `neoth-self-wiki`) so the design corpus surfaces on recall. Prior
        /// self-wiki rows are revoked first (idempotent). Ignored on dry-run.
        #[arg(long)]
        ingest: bool,
    },
    /// Copy a curated Markdown/YAML vault template into Obsidian and optionally
    /// ingest reviewed Markdown notes into NEOTH memory. Raw/restricted source
    /// folders stay copy-only unless the manifest explicitly marks them safe.
    Preload {
        /// Obsidian vault root to copy the preload into.
        vault: PathBuf,
        /// Curated vault-template directory. Must contain `preload_manifest.yaml`.
        #[arg(long, value_name = "DIR")]
        template: PathBuf,
        /// Subdirectory inside the vault for copied preload files.
        #[arg(long, default_value = "NEOTH-Preload")]
        subdir: PathBuf,
        /// Print the plan without writing vault files, state, or memory rows.
        #[arg(long)]
        dry_run: bool,
        /// Also ingest manifest-approved Markdown notes into `idx_groundtruth`.
        #[arg(long)]
        ingest: bool,
        /// Override the preload hash-state JSON path (mostly for tests).
        #[arg(long, value_name = "FILE")]
        state: Option<PathBuf>,
    },
}

#[derive(Clone, Debug, Default)]
pub struct SyncStats {
    pub considered: usize,
    pub copied: usize,
    pub skipped_identical: usize,
    pub skipped_dry_run: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PreloadStats {
    pub files_considered: usize,
    pub files_copied: usize,
    pub skipped_identical: usize,
    pub skipped_dry_run: usize,
    pub skipped_policy: usize,
    pub restricted_files: usize,
    pub ingest_candidates: usize,
    pub ingested_chunks: usize,
    pub revoked_chunks: usize,
    pub dry_run: bool,
    pub ingest: bool,
    pub vault_subdir: String,
    pub state_path: String,
}

pub async fn run_obsidian(args: ObsidianArgs) -> Result<()> {
    let root = args
        .archive_root
        .clone()
        .unwrap_or_else(archive::default_archive_root);
    match args.action {
        ObsidianAction::Status => {
            // Fail loudly on config load failure — silent defaults would mislead.
            let cfg = crate::config::FreedomConfig::load_from_path(
                &crate::config::FreedomConfig::default_path(),
            )
            .context("load freedom.yaml for obsidian status")?;
            render_status(&cfg, args.output);
        }
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
            ingest,
        } => {
            // F75 — apply the same path-traversal hardening the `sync` arm uses:
            // `--subdir` must be a single normal component (no `..` / absolute /
            // nested / drive-relative) before it is joined onto the vault root.
            validate_subdir(&subdir)?;
            let out_dir = vault.join(&subdir);
            let (stats, slugs) = crate::wiki::build_wiki(&source_dir, &out_dir, dry_run)?;
            render_wiki_build(&stats, &slugs, &out_dir, args.output);
            if ingest && !dry_run {
                let sources = crate::wiki::discover_sources(&source_dir)?;
                let conn = crate::memory::store::open(&crate::memory::store::default_path())
                    .context("open views.db for self-wiki ground-truth ingest")?;
                let now_ns = crate::time::now_unix_ns_i64();
                let ist = crate::wiki::ingest_sources(&conn, &sources, now_ns)?;
                println!(
                    "self-wiki ingest: {} ground-truth pointer(s) inserted, {} prior revoked (scope {})",
                    ist.inserted,
                    ist.revoked,
                    crate::wiki::WIKI_SCOPE
                );
            }
        }
        ObsidianAction::Preload {
            vault,
            template,
            subdir,
            dry_run,
            ingest,
            state,
        } => {
            validate_subdir(&subdir).with_context(|| {
                format!(
                    "invalid preload subdir {}: must be a simple name, not a traversal path",
                    subdir.display()
                )
            })?;
            let stats = preload_template(
                &template,
                &vault,
                &subdir,
                dry_run,
                ingest,
                state.as_deref(),
                None,
            )
            .await?;
            render_preload(stats, args.output);
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
pub(crate) fn default_vault_path() -> PathBuf {
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
    // OH-14 — default Obsidian graph config: colour-codes #spec/#design tags
    // + shows orphan nodes so NEOTH-Wiki pages surface in the graph view
    // immediately even before the operator adds backlinks.
    write_if_absent(
        vault,
        Path::new(".obsidian/graph.json"),
        GRAPH_JSON,
        &mut created,
        &mut skipped,
    )?;
    // OH-14 — empty Obsidian property types registry. Obsidian would create
    // this itself on first vault open; shipping it pre-populated avoids a
    // "vault modified externally" dialog for the operator.
    write_if_absent(
        vault,
        Path::new(".obsidian/types.json"),
        TYPES_JSON,
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

/// OH-14 — default graph config embedded from the bundled asset.
/// Shipped via both `scaffold_vault` (CLI) and `bootstrap_files()` (wizard).
const GRAPH_JSON: &str = include_str!("../../assets/obsidian_vault/.obsidian/graph.json");

/// OH-14 — empty Obsidian property types registry.
const TYPES_JSON: &str = include_str!("../../assets/obsidian_vault/.obsidian/types.json");

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
pub(crate) fn validate_subdir(subdir: &Path) -> Result<()> {
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

    // neoth(IGNIS-04): detect cloud-sync conflict files before writing.
    // Warn (do not block) so the operator can resolve collisions at their
    // own pace while NEOTH continues to sync.
    {
        let conflict_report = detect_sync_conflicts(vault);
        if let Some(msg) = conflict_report.describe() {
            tracing::warn!(conflict_count = conflict_report.conflicts.len(), "{}", msg);
        }
    }

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

    // IGNIS-02: mtime cache — skip the file scan for day directories whose
    // mtime is unchanged since the last sync_archive call on this instance.
    // Each `sync_archive` call gets a fresh cache (function-scoped), so the
    // guard only elides redundant within-call re-reads on the same directory.
    // For cross-call mtime caching, callers can pass a pre-built cache via
    // the daemon layer (see obsidian_sync_task.rs wiring point).
    //
    // neoth: obsidian_sync_task::run should hold a `DirMtimeCache` across
    // ticks and thread it into sync_archive (requires a signature extension
    // to `pub async fn sync_archive(…, mtime_cache: &mut DirMtimeCache)`).
    let mut mtime_cache = DirMtimeCache::new();

    // IGNIS-01: coalesce all writes for this sync pass into a single flush
    // to avoid one fsync/rename per note on slow or network-mounted vaults.
    let mut coalescer = WriteCoalescer::new();

    // neoth(IGNIS-03): wire EchoGuard here once reverse-sync watcher lands.
    // Pattern:
    //   let guard: &mut EchoGuard = …;          // passed in from daemon state
    //   guard.register_write(&dst, &src_bytes); // after coalescer.flush()
    // This prevents the watcher from re-syncing files NEOTH just wrote.

    let mut day_rd = tokio::fs::read_dir(&sessions_root)
        .await
        .with_context(|| format!("read archive root {}", sessions_root.display()))?;
    while let Some(day_entry) = day_rd.next_entry().await? {
        if !day_entry.file_type().await?.is_dir() {
            continue;
        }
        let day_src = day_entry.path();
        let day_name = day_entry.file_name().to_string_lossy().into_owned();
        let day_dst = dest_root.join(&day_name);

        // IGNIS-02: skip the per-file scan if the source day directory's
        // mtime is unchanged AND the destination day dir already exists.
        // On the very first sync (dest absent) we always walk.
        if !dry_run && day_dst.exists() && !mtime_cache.is_changed(&day_src) {
            continue;
        }

        if !dry_run {
            tokio::fs::create_dir_all(&day_dst)
                .await
                .with_context(|| format!("create day dir {}", day_dst.display()))?;
        }

        let mut file_rd = tokio::fs::read_dir(&day_src).await?;
        while let Some(file_entry) = file_rd.next_entry().await? {
            let path = file_entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("md") {
                continue;
            }
            stats.considered += 1;
            let dst = day_dst.join(path.file_name().unwrap());

            if dry_run {
                stats.skipped_dry_run += 1;
                continue;
            }

            // IGNIS-01: read the source bytes once and queue into the
            // coalescer; it will skip files whose vault copy is identical.
            let src_bytes = tokio::fs::read(&path)
                .await
                .with_context(|| format!("read {}", path.display()))?;
            coalescer.push(dst, src_bytes);
        }
    }

    // IGNIS-01: flush all queued writes in one pass. Skipped-identical
    // entries come back so we can update stats accurately.
    if !dry_run {
        let (written, skipped_identical) = coalescer.flush().context("WriteCoalescer flush")?;
        stats.copied = written;
        stats.skipped_identical = skipped_identical;
    }

    Ok(stats)
}

#[derive(Clone, Debug, Default, Deserialize)]
struct PreloadManifest {
    #[serde(default)]
    neoth_import_contract: PreloadImportContract,
    #[serde(default)]
    sections: Vec<PreloadSection>,
}

#[derive(Clone, Debug, Deserialize)]
struct PreloadImportContract {
    #[serde(default = "default_vault_preload_subdir")]
    default_vault_subdir: String,
    #[serde(default = "default_source_tag")]
    default_source_tag: String,
    #[serde(default = "default_preload_scope")]
    default_scope: String,
    #[serde(default = "default_preload_trust")]
    default_trust: String,
    #[serde(default = "default_preload_chunking")]
    default_chunking: String,
    #[serde(default)]
    ingest_raw_sources_by_default: bool,
    #[serde(default)]
    ingest_operational_security_payloads_by_default: bool,
    #[serde(default)]
    echo_loop_guard: EchoLoopGuard,
}

impl Default for PreloadImportContract {
    fn default() -> Self {
        Self {
            default_vault_subdir: default_vault_preload_subdir(),
            default_source_tag: default_source_tag(),
            default_scope: default_preload_scope(),
            default_trust: default_preload_trust(),
            default_chunking: default_preload_chunking(),
            ingest_raw_sources_by_default: false,
            ingest_operational_security_payloads_by_default: false,
            echo_loop_guard: EchoLoopGuard::default(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
struct EchoLoopGuard {
    #[serde(default)]
    skip_generated_dirs: Vec<String>,
    #[serde(default)]
    skip_dirs: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct PreloadSection {
    path: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    trust: String,
    #[serde(default = "default_true")]
    ingest: bool,
    #[serde(default = "default_true")]
    copy_to_vault: bool,
    #[serde(default)]
    chunking: String,
}

impl Default for PreloadSection {
    fn default() -> Self {
        Self {
            path: String::new(),
            scope: default_preload_scope(),
            trust: default_preload_trust(),
            ingest: true,
            copy_to_vault: true,
            chunking: default_preload_chunking(),
        }
    }
}

#[derive(Clone, Debug)]
struct EffectivePreloadPolicy {
    scope: String,
    trust: String,
    chunking: String,
    ingest: bool,
    copy_to_vault: bool,
    restricted: bool,
}

#[derive(Clone, Debug)]
struct PreloadFile {
    rel: PathBuf,
    rel_key: String,
    bytes: Vec<u8>,
    hash: String,
    is_markdown: bool,
    policy: EffectivePreloadPolicy,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct PreloadState {
    #[serde(default)]
    copied_hashes: BTreeMap<String, String>,
    #[serde(default)]
    ingested_hashes: BTreeMap<String, String>,
}

fn default_true() -> bool {
    true
}

fn default_vault_preload_subdir() -> String {
    "NEOTH-Preload".to_string()
}

fn default_source_tag() -> String {
    "neoth-preload".to_string()
}

fn default_preload_scope() -> String {
    "l6-vault".to_string()
}

fn default_preload_trust() -> String {
    "curated-reference".to_string()
}

fn default_preload_chunking() -> String {
    "markdown-heading".to_string()
}

fn default_preload_state_path() -> PathBuf {
    crate::config::FreedomConfig::default_neoth_home().join("obsidian_preload_state.json")
}

/// L6-PRELOAD-AUTORUN-01 — distinct state path per template root.
///
/// Each `knowledge_preload_dirs` entry and the primary
/// `obsidian_preload_template_dir` uses a separate state file keyed by a
/// 64-bit hash of the template path.  Prevents cross-root hash collisions
/// when two roots share a file with the same relative name.
///
/// Pure function — no env reads, no I/O.  Stable across restarts for the
/// same path; different paths always produce different names.
pub(crate) fn preload_state_path_for(template: &Path) -> PathBuf {
    use std::hash::Hash;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    template.hash(&mut h);
    let key = std::hash::Hasher::finish(&h);
    crate::config::FreedomConfig::default_neoth_home()
        .join(format!("obsidian_preload_state_{key:016x}.json"))
}

/// Gate result returned by [`preload_autorun_decision`].
///
/// The enum keeps side effects (warn log) out of the decision function so
/// the function stays pure and tests can match on the variant without any
/// tracing subscriber being present.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PreloadDecision {
    /// `obsidian_preload_template_dir` is unset — no-op, no log.
    Skip,
    /// Template dir is set but `obsidian_vault` is not — caller should warn.
    WarnNoVault,
    /// Both are set; caller should spawn the one-shot preload task.
    Run {
        vault: PathBuf,
        template_dir: PathBuf,
        /// Empty `PathBuf` means the manifest's `default_vault_subdir` is used.
        subdir: PathBuf,
    },
}

/// Pure gate: derive from config whether the preload autorun should fire.
///
/// No side effects (no logging, no I/O).  Callers handle the warn case.
/// `Skip` is the common case for installs that have not configured preload.
pub(crate) fn preload_autorun_decision(cfg: &crate::config::FreedomConfig) -> PreloadDecision {
    let template_str = match cfg.obsidian_preload_template_dir.as_deref() {
        Some(s) => s,
        None => return PreloadDecision::Skip,
    };
    let vault = match cfg.obsidian_vault.as_deref() {
        Some(v) => PathBuf::from(v),
        None => return PreloadDecision::WarnNoVault,
    };
    let subdir = cfg
        .obsidian_preload_subdir
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_default(); // empty → manifest's default_vault_subdir
    PreloadDecision::Run {
        vault,
        template_dir: PathBuf::from(template_str),
        subdir,
    }
}

/// Returns `true` when `root` contains a `preload_manifest.yaml` file.
///
/// Used by `spawn_obsidian_preload` to gate each `knowledge_preload_dirs`
/// entry.  Extracted as a named function so tests can assert the skip logic
/// independently of the async spawn path.
pub(crate) fn knowledge_root_has_manifest(root: &Path) -> bool {
    root.join("preload_manifest.yaml").exists()
}

fn load_preload_manifest(template: &Path) -> Result<PreloadManifest> {
    let path = template.join("preload_manifest.yaml");
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("read preload manifest {}", path.display()))?;
    serde_yaml::from_str(&body)
        .with_context(|| format!("parse preload manifest {}", path.display()))
}

fn load_preload_state(path: &Path) -> Result<PreloadState> {
    if !path.exists() {
        return Ok(PreloadState::default());
    }
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read preload state {}", path.display()))?;
    serde_json::from_str(&body).with_context(|| format!("parse preload state {}", path.display()))
}

fn save_preload_state(path: &Path, state: &PreloadState) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create preload state dir {}", parent.display()))?;
    }
    let body = serde_json::to_vec_pretty(state).context("serialize preload state")?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, body).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))
}

fn normalize_rel(path: &Path) -> String {
    path.components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn section_matches(rel_key: &str, section_path: &str) -> bool {
    let p = section_path.trim_matches('/').replace('\\', "/");
    if p.is_empty() {
        return true;
    }
    rel_key == p
        || rel_key
            .strip_prefix(&p)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn effective_policy(manifest: &PreloadManifest, rel_key: &str) -> EffectivePreloadPolicy {
    let mut best: Option<&PreloadSection> = None;
    for section in &manifest.sections {
        if section_matches(rel_key, &section.path) {
            match best {
                Some(prev) if prev.path.len() >= section.path.len() => {}
                _ => best = Some(section),
            }
        }
    }
    let contract = &manifest.neoth_import_contract;
    let (scope, trust, chunking, ingest, copy_to_vault, section_path) = match best {
        Some(section) => (
            if section.scope.is_empty() {
                contract.default_scope.clone()
            } else {
                section.scope.clone()
            },
            if section.trust.is_empty() {
                contract.default_trust.clone()
            } else {
                section.trust.clone()
            },
            if section.chunking.is_empty() {
                contract.default_chunking.clone()
            } else {
                section.chunking.clone()
            },
            section.ingest,
            section.copy_to_vault,
            section.path.as_str(),
        ),
        None => (
            contract.default_scope.clone(),
            contract.default_trust.clone(),
            contract.default_chunking.clone(),
            true,
            true,
            "",
        ),
    };

    let raw_or_restricted = section_path.eq_ignore_ascii_case("sources")
        || trust.eq_ignore_ascii_case("raw-source")
        || trust.eq_ignore_ascii_case("runtime-log");
    let operational_security = scope.eq_ignore_ascii_case("l6-sources")
        || scope.eq_ignore_ascii_case("offline-security-restricted")
        || rel_key.contains("Restricted-Exploit-Code");
    let ingest_allowed = ingest
        && (!raw_or_restricted || contract.ingest_raw_sources_by_default)
        && (!operational_security || contract.ingest_operational_security_payloads_by_default);

    EffectivePreloadPolicy {
        scope,
        trust,
        chunking,
        ingest: ingest_allowed,
        copy_to_vault,
        restricted: raw_or_restricted || operational_security,
    }
}

fn skip_dir_name(manifest: &PreloadManifest, name: &str) -> bool {
    if name.starts_with('.') {
        return true;
    }
    let guard = &manifest.neoth_import_contract.echo_loop_guard;
    guard.skip_dirs.iter().any(|d| d == name) || guard.skip_generated_dirs.iter().any(|d| d == name)
}

fn allowed_preload_extension(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|s| s.to_str())
            .map(|s| s.to_ascii_lowercase()),
        Some(ext)
            if matches!(
                ext.as_str(),
                "md" | "markdown" | "txt" | "yaml" | "yml" | "json"
            )
    )
}

fn collect_preload_files(
    template: &Path,
    manifest: &PreloadManifest,
) -> Result<(Vec<PreloadFile>, usize)> {
    fn walk(
        root: &Path,
        dir: &Path,
        manifest: &PreloadManifest,
        out: &mut Vec<PreloadFile>,
        skipped_policy: &mut usize,
    ) -> Result<()> {
        let mut entries = std::fs::read_dir(dir)
            .with_context(|| format!("read preload dir {}", dir.display()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .with_context(|| format!("read entries in {}", dir.display()))?;
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let meta = std::fs::symlink_metadata(&path)
                .with_context(|| format!("stat preload path {}", path.display()))?;
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                if skip_dir_name(manifest, &name) {
                    continue;
                }
                walk(root, &path, manifest, out, skipped_policy)?;
                continue;
            }
            if !meta.is_file() || name.starts_with('.') || !allowed_preload_extension(&path) {
                continue;
            }

            let rel = path
                .strip_prefix(root)
                .with_context(|| format!("strip preload root from {}", path.display()))?
                .to_path_buf();
            let rel_key = normalize_rel(&rel);
            if rel_key.eq_ignore_ascii_case("preload_manifest.yaml")
                || rel_key.eq_ignore_ascii_case("preload_manifest.yml")
            {
                continue;
            }
            let policy = effective_policy(manifest, &rel_key);
            if !policy.copy_to_vault {
                *skipped_policy += 1;
                continue;
            }
            let is_markdown = path.extension().and_then(|s| s.to_str()).is_some_and(|s| {
                s.eq_ignore_ascii_case("md") || s.eq_ignore_ascii_case("markdown")
            });
            let raw = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let bytes = if is_markdown {
                let text = String::from_utf8_lossy(&raw);
                normalize_markdown_frontmatter(&text, manifest, &policy).into_bytes()
            } else {
                raw
            };
            let hash = format!("{:016x}", xxhash_rust::xxh3::xxh3_64(&bytes));
            out.push(PreloadFile {
                rel,
                rel_key,
                bytes,
                hash,
                is_markdown,
                policy,
            });
        }
        Ok(())
    }

    let mut files = Vec::new();
    let mut skipped_policy = 0usize;
    walk(
        template,
        template,
        manifest,
        &mut files,
        &mut skipped_policy,
    )?;
    files.sort_by(|a, b| a.rel_key.cmp(&b.rel_key));
    Ok((files, skipped_policy))
}

fn frontmatter_has_key(frontmatter: &str, key: &str) -> bool {
    frontmatter
        .lines()
        .any(|line| line.trim_start().starts_with(&format!("{key}:")))
}

fn frontmatter_fields(
    manifest: &PreloadManifest,
    policy: &EffectivePreloadPolicy,
) -> Vec<(&'static str, String)> {
    vec![
        (
            "source",
            manifest.neoth_import_contract.default_source_tag.clone(),
        ),
        ("neoth_preload", "true".to_string()),
        ("neoth_scope", policy.scope.clone()),
        ("neoth_trust", policy.trust.clone()),
        ("neoth_chunking", policy.chunking.clone()),
    ]
}

fn normalize_markdown_frontmatter(
    text: &str,
    manifest: &PreloadManifest,
    policy: &EffectivePreloadPolicy,
) -> String {
    let text = text.replace("\r\n", "\n");
    let fields = frontmatter_fields(manifest, policy);
    if let Some(rest) = text.strip_prefix("---\n") {
        if let Some(end) = rest.find("\n---\n") {
            let (frontmatter, body_with_delim) = rest.split_at(end);
            let body = &body_with_delim["\n---\n".len()..];
            let mut out = String::from("---\n");
            out.push_str(frontmatter);
            if !frontmatter.ends_with('\n') && !frontmatter.is_empty() {
                out.push('\n');
            }
            for (key, value) in fields {
                if !frontmatter_has_key(frontmatter, key) {
                    out.push_str(key);
                    out.push_str(": ");
                    out.push_str(&value);
                    out.push('\n');
                }
            }
            out.push_str("---\n");
            out.push_str(body);
            return out;
        }
    }

    let mut out = String::from("---\n");
    for (key, value) in fields {
        out.push_str(key);
        out.push_str(": ");
        out.push_str(&value);
        out.push('\n');
    }
    out.push_str("---\n\n");
    out.push_str(&text);
    out
}

fn strip_frontmatter(text: &str) -> &str {
    if let Some(rest) = text.strip_prefix("---\n") {
        if let Some(end) = rest.find("\n---\n") {
            return &rest[end + "\n---\n".len()..];
        }
    }
    text
}

fn clean_statement_text(text: &str) -> String {
    let mut out = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    const MAX_CHARS: usize = 1800;
    if out.chars().count() > MAX_CHARS {
        out = out.chars().take(MAX_CHARS).collect::<String>();
        out.push_str("...");
    }
    out
}

fn markdown_chunks(markdown: &str, chunking: &str) -> Vec<(String, String)> {
    let body = strip_frontmatter(markdown).trim();
    if body.is_empty() || chunking.eq_ignore_ascii_case("none") {
        return Vec::new();
    }
    if chunking.eq_ignore_ascii_case("whole-note") {
        return vec![("whole-note".to_string(), clean_statement_text(body))];
    }

    let mut chunks = Vec::new();
    let mut heading = "preamble".to_string();
    let mut buf = String::new();
    let flush = |chunks: &mut Vec<(String, String)>, heading: &str, buf: &mut String| {
        let clean = clean_statement_text(buf);
        if !clean.is_empty() {
            chunks.push((heading.to_string(), clean));
        }
        buf.clear();
    };

    for line in body.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            flush(&mut chunks, &heading, &mut buf);
            heading = trimmed.trim_start_matches('#').trim().to_string();
            if heading.is_empty() {
                heading = "heading".to_string();
            }
        } else {
            buf.push_str(line);
            buf.push('\n');
        }
    }
    flush(&mut chunks, &heading, &mut buf);
    if chunks.is_empty() {
        chunks.push(("whole-note".to_string(), clean_statement_text(body)));
    }
    chunks
}

fn preload_scope(policy: &EffectivePreloadPolicy) -> String {
    format!("neoth-preload:{}", policy.scope)
}

fn preload_statement(
    rel_key: &str,
    policy: &EffectivePreloadPolicy,
    heading: &str,
    chunk: &str,
) -> String {
    format!(
        "NEOTH preload chunk source_path={} scope={} trust={} heading=\"{}\": {}",
        rel_key, policy.scope, policy.trust, heading, chunk
    )
}

fn revoke_existing_preload_chunks(
    conn: &rusqlite::Connection,
    scope: &str,
    rel_key: &str,
    now_ns: i64,
) -> Result<usize> {
    let marker = format!("source_path={rel_key} ");
    let mut revoked = 0usize;
    for row in crate::memory::groundtruth::list_for_scope(conn, scope)? {
        if row.revoked_at.is_none() && row.statement.contains(&marker) {
            crate::memory::groundtruth::revoke(conn, row.id, now_ns)?;
            revoked += 1;
        }
    }
    Ok(revoked)
}

pub async fn preload_template(
    template: &Path,
    vault: &Path,
    subdir: &Path,
    dry_run: bool,
    ingest: bool,
    state_override: Option<&Path>,
    views_db_override: Option<&Path>,
) -> Result<PreloadStats> {
    validate_subdir(subdir).with_context(|| {
        format!(
            "invalid preload subdir {}: must be a simple name, not a traversal path",
            subdir.display()
        )
    })?;
    if !template.is_dir() {
        anyhow::bail!(
            "preload template is not a directory: {}",
            template.display()
        );
    }

    let manifest = load_preload_manifest(template)?;
    let effective_subdir = if subdir.as_os_str().is_empty() {
        PathBuf::from(&manifest.neoth_import_contract.default_vault_subdir)
    } else {
        subdir.to_path_buf()
    };
    validate_subdir(&effective_subdir)?;

    let state_path = state_override
        .map(Path::to_path_buf)
        .unwrap_or_else(default_preload_state_path);
    let mut state = load_preload_state(&state_path)?;
    let (files, skipped_policy) = collect_preload_files(template, &manifest)?;

    let mut stats = PreloadStats {
        files_considered: files.len(),
        skipped_policy,
        dry_run,
        ingest,
        vault_subdir: effective_subdir.display().to_string(),
        state_path: state_path.display().to_string(),
        ..PreloadStats::default()
    };

    let mut coalescer = WriteCoalescer::new();
    let conn = if ingest && !dry_run {
        let db_path = views_db_override
            .map(Path::to_path_buf)
            .unwrap_or_else(crate::memory::store::default_path);
        Some(crate::memory::store::open(&db_path).with_context(|| {
            format!("open views.db for preload ingest at {}", db_path.display())
        })?)
    } else {
        None
    };
    let now_ns = crate::time::now_unix_ns_i64();

    for file in &files {
        if file.policy.restricted {
            stats.restricted_files += 1;
        }
        let dst = vault.join(&effective_subdir).join(&file.rel);
        if dry_run {
            stats.skipped_dry_run += 1;
        } else {
            coalescer.push(dst, file.bytes.clone());
            state
                .copied_hashes
                .insert(file.rel_key.clone(), file.hash.clone());
        }

        if file.is_markdown && file.policy.ingest {
            stats.ingest_candidates += 1;
            if ingest && !dry_run {
                let old_hash = state.ingested_hashes.get(&file.rel_key);
                if old_hash == Some(&file.hash) {
                    continue;
                }
                let markdown = String::from_utf8_lossy(&file.bytes);
                let chunks = markdown_chunks(&markdown, &file.policy.chunking);
                if chunks.is_empty() {
                    state
                        .ingested_hashes
                        .insert(file.rel_key.clone(), file.hash.clone());
                    continue;
                }
                let scope = preload_scope(&file.policy);
                if let Some(conn) = conn.as_ref() {
                    stats.revoked_chunks +=
                        revoke_existing_preload_chunks(conn, &scope, &file.rel_key, now_ns)?;
                    for (heading, chunk) in chunks {
                        crate::memory::groundtruth::insert(
                            conn,
                            &preload_statement(&file.rel_key, &file.policy, &heading, &chunk),
                            &crate::memory::groundtruth::Source::ImportObsidian,
                            &scope,
                            now_ns,
                        )?;
                        stats.ingested_chunks += 1;
                    }
                }
                state
                    .ingested_hashes
                    .insert(file.rel_key.clone(), file.hash.clone());
            }
        }
    }

    if !dry_run {
        let (written, skipped_identical) =
            coalescer.flush().context("preload WriteCoalescer flush")?;
        stats.files_copied = written;
        stats.skipped_identical = skipped_identical;
        save_preload_state(&state_path, &state)?;
    }

    Ok(stats)
}

fn render_preload(stats: PreloadStats, output: OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string_pretty(&stats).unwrap_or_default()
            );
        }
        OutputFormat::Table => {
            let mode = if stats.dry_run {
                "preload dry-run"
            } else {
                "preload"
            };
            println!(
                "obsidian {mode}: {} considered, {} copied, {} unchanged, {} dry-run, {} policy-skipped, {} restricted, {} ingest-candidate, {} ingested chunk(s), {} revoked chunk(s)",
                stats.files_considered,
                stats.files_copied,
                stats.skipped_identical,
                stats.skipped_dry_run,
                stats.skipped_policy,
                stats.restricted_files,
                stats.ingest_candidates,
                stats.ingested_chunks,
                stats.revoked_chunks,
            );
            println!("vault subdir: {}", stats.vault_subdir);
            println!("state: {}", stats.state_path);
        }
    }
}

// IGNIS-01: identity check now handled inside WriteCoalescer::flush; kept
// for reference and test-helper use.
#[allow(dead_code)]
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

/// Report the Obsidian integration config. Pure read, no side effects.
fn render_status(cfg: &crate::config::FreedomConfig, output: OutputFormat) {
    let vault = cfg.obsidian_vault.as_deref().unwrap_or("");
    let subdir = cfg.obsidian_subdir.as_deref().unwrap_or("NEOTH-sessions");
    let auto_sync_secs = cfg.obsidian_auto_sync_secs;
    let wiki_rebuild_secs = cfg.obsidian_wiki_rebuild_secs;
    let vault_reader_enabled = cfg.obsidian_vault_reader_enabled;
    let configured = !vault.is_empty();

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "configured": configured,
                    "obsidian_vault": cfg.obsidian_vault,
                    "obsidian_subdir": cfg.obsidian_subdir,
                    "obsidian_auto_sync_secs": auto_sync_secs,
                    "obsidian_wiki_rebuild_secs": wiki_rebuild_secs,
                    "obsidian_vault_reader_enabled": vault_reader_enabled,
                    "obsidian_preload_template_dir": cfg.obsidian_preload_template_dir,
                    "obsidian_preload_subdir": cfg.obsidian_preload_subdir,
                    "knowledge_preload_dirs": cfg.knowledge_preload_dirs,
                })
            );
        }
        OutputFormat::Table => {
            if !configured {
                println!("obsidian vault: not configured (set obsidian_vault in freedom.yaml)");
                return;
            }
            println!("obsidian vault:          {vault}");
            println!("session subdir:          {subdir}");
            println!(
                "auto-sync interval:      {}",
                auto_sync_secs
                    .map(|s| format!("{s}s"))
                    .unwrap_or_else(|| "off".to_string())
            );
            println!(
                "wiki-rebuild interval:   {}",
                wiki_rebuild_secs
                    .map(|s| format!("{s}s"))
                    .unwrap_or_else(|| "off".to_string())
            );
            println!(
                "vault reader:            {}",
                if vault_reader_enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            if let Some(template) = cfg.obsidian_preload_template_dir.as_deref() {
                println!("preload template:        {template}");
            }
            if !cfg.knowledge_preload_dirs.is_empty() {
                println!(
                    "knowledge preload dirs:  {}",
                    cfg.knowledge_preload_dirs.join(", ")
                );
            }
        }
    }
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

    fn write_template_file(root: &Path, rel: &str, body: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn write_preload_manifest(root: &Path) {
        write_template_file(
            root,
            "preload_manifest.yaml",
            r#"version: 1
neoth_import_contract:
  default_source_tag: neoth-preload
  default_vault_subdir: NEOTH-Preload
  default_scope: l6-vault
  default_trust: curated-reference
  default_chunking: markdown-heading
  ingest_raw_sources_by_default: false
  ingest_operational_security_payloads_by_default: false
  echo_loop_guard:
    skip_generated_dirs:
      - NEOTH-Wiki
    skip_dirs:
      - logs
sections:
  - path: wiki
    scope: l6-wiki
    trust: curated-reference
    ingest: true
    copy_to_vault: true
    chunking: markdown-heading
  - path: sources
    scope: l6-sources
    trust: raw-source
    ingest: false
    copy_to_vault: true
    chunking: none
  - path: logs
    scope: l6-logs
    trust: runtime-log
    ingest: false
    copy_to_vault: false
    chunking: none
"#,
        );
    }

    #[tokio::test]
    async fn preload_dry_run_excludes_logs_and_restricted_sources_from_ingest() {
        let dir = tempdir().unwrap();
        let template = dir.path().join("template");
        write_preload_manifest(&template);
        write_template_file(&template, "wiki/a.md", "# A\n\nSafe summary");
        write_template_file(&template, "sources/payloads.md", "# Raw\n\npayload list");
        write_template_file(&template, "logs/runtime.md", "# Log\n\nignore");
        write_template_file(
            &template,
            "NEOTH-Wiki/generated.md",
            "# Generated\n\nignore",
        );
        let state = dir.path().join("state.json");
        let views_db = dir.path().join("views.db");

        let stats = preload_template(
            &template,
            &dir.path().join("vault"),
            &PathBuf::from("NEOTH-Preload"),
            true,
            true,
            Some(&state),
            Some(&views_db),
        )
        .await
        .unwrap();

        assert_eq!(stats.files_considered, 2, "wiki + sources");
        assert_eq!(stats.skipped_dry_run, 2);
        assert_eq!(stats.ingest_candidates, 1, "only wiki/a.md is ingestable");
        assert_eq!(
            stats.restricted_files, 1,
            "sources/ is restricted copy-only"
        );
        assert!(!dir.path().join("vault/NEOTH-Preload").exists());
    }

    #[tokio::test]
    async fn preload_copies_relative_paths_and_normalizes_frontmatter() {
        let dir = tempdir().unwrap();
        let template = dir.path().join("template");
        let vault = dir.path().join("vault");
        let state = dir.path().join("state.json");
        let views_db = dir.path().join("views.db");
        write_preload_manifest(&template);
        write_template_file(&template, "wiki/a.md", "# A\n\nSafe summary");
        write_template_file(&template, "sources/raw.md", "# Raw\n\ncopy only");

        let stats = preload_template(
            &template,
            &vault,
            &PathBuf::from("NEOTH-Preload"),
            false,
            false,
            Some(&state),
            Some(&views_db),
        )
        .await
        .unwrap();
        assert_eq!(stats.files_copied, 2, "wiki + sources");

        let copied = std::fs::read_to_string(vault.join("NEOTH-Preload/wiki/a.md")).unwrap();
        assert!(copied.starts_with("---\n"));
        assert!(copied.contains("source: neoth-preload"));
        assert!(copied.contains("neoth_preload: true"));
        assert!(copied.contains("neoth_scope: l6-wiki"));

        let second = preload_template(
            &template,
            &vault,
            &PathBuf::from("NEOTH-Preload"),
            false,
            false,
            Some(&state),
            Some(&views_db),
        )
        .await
        .unwrap();
        assert_eq!(second.files_copied, 0);
        assert_eq!(second.skipped_identical, 2);
    }

    #[tokio::test]
    async fn preload_ingest_is_hash_idempotent_and_revokes_changed_file_chunks() {
        let dir = tempdir().unwrap();
        let template = dir.path().join("template");
        let vault = dir.path().join("vault");
        let state = dir.path().join("state.json");
        let views_db = dir.path().join("views.db");
        write_preload_manifest(&template);
        write_template_file(&template, "wiki/a.md", "# Alpha\n\nBody one");

        let first = preload_template(
            &template,
            &vault,
            &PathBuf::from("NEOTH-Preload"),
            false,
            true,
            Some(&state),
            Some(&views_db),
        )
        .await
        .unwrap();
        assert_eq!(first.ingest_candidates, 1);
        assert_eq!(first.ingested_chunks, 1);
        assert_eq!(first.revoked_chunks, 0);

        let second = preload_template(
            &template,
            &vault,
            &PathBuf::from("NEOTH-Preload"),
            false,
            true,
            Some(&state),
            Some(&views_db),
        )
        .await
        .unwrap();
        assert_eq!(second.ingested_chunks, 0, "unchanged hash skips ingest");
        assert_eq!(second.revoked_chunks, 0);

        write_template_file(&template, "wiki/a.md", "# Alpha\n\nBody two");
        let third = preload_template(
            &template,
            &vault,
            &PathBuf::from("NEOTH-Preload"),
            false,
            true,
            Some(&state),
            Some(&views_db),
        )
        .await
        .unwrap();
        assert_eq!(third.ingested_chunks, 1);
        assert_eq!(
            third.revoked_chunks, 1,
            "old chunk for same source_path revoked"
        );

        let conn = crate::memory::store::open(&views_db).unwrap();
        let rows =
            crate::memory::groundtruth::list_for_scope(&conn, "neoth-preload:l6-wiki").unwrap();
        assert_eq!(
            rows.len(),
            1,
            "only the latest changed note chunk is active"
        );
        assert!(rows[0].statement.contains("Body two"));
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
        // OH-14 — graph + types config must be scaffolded on init.
        assert!(
            created.contains(&".obsidian/graph.json".to_string()),
            "graph.json must be created on init; created={created:?}"
        );
        assert!(
            created.contains(&".obsidian/types.json".to_string()),
            "types.json must be created on init; created={created:?}"
        );
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

    // ── status JSON shape tests ───────────────────────────────────────────────

    /// `status` JSON object must contain all expected keys and reflect the
    /// `configured` flag correctly when `obsidian_vault` is set.
    #[test]
    fn status_json_shape_configured() {
        let mut cfg = crate::config::FreedomConfig::default();
        cfg.obsidian_vault = Some("/home/op/vault".to_string());
        cfg.obsidian_subdir = Some("NEOTH-sessions".to_string());
        cfg.obsidian_auto_sync_secs = Some(3600);
        cfg.obsidian_wiki_rebuild_secs = None;
        cfg.obsidian_vault_reader_enabled = true;

        let v = serde_json::json!({
            "configured": cfg.obsidian_vault.as_ref().map(|s| !s.is_empty()).unwrap_or(false),
            "obsidian_vault": cfg.obsidian_vault,
            "obsidian_subdir": cfg.obsidian_subdir,
            "obsidian_auto_sync_secs": cfg.obsidian_auto_sync_secs,
            "obsidian_wiki_rebuild_secs": cfg.obsidian_wiki_rebuild_secs,
            "obsidian_vault_reader_enabled": cfg.obsidian_vault_reader_enabled,
        });

        assert_eq!(v["configured"], true);
        assert_eq!(v["obsidian_vault"], "/home/op/vault");
        assert_eq!(v["obsidian_subdir"], "NEOTH-sessions");
        assert_eq!(v["obsidian_auto_sync_secs"], 3600);
        assert!(v["obsidian_wiki_rebuild_secs"].is_null());
        assert_eq!(v["obsidian_vault_reader_enabled"], true);
    }

    /// When `obsidian_vault` is `None`, `configured` must be `false`.
    #[test]
    fn status_json_shape_unconfigured() {
        let cfg = crate::config::FreedomConfig::default();
        let configured = cfg
            .obsidian_vault
            .as_deref()
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let v = serde_json::json!({
            "configured": configured,
            "obsidian_vault": cfg.obsidian_vault,
        });
        assert_eq!(v["configured"], false);
        assert!(v["obsidian_vault"].is_null());
    }

    // ── L6-PRELOAD-AUTORUN-01: gate + state-path helpers ─────────────────

    #[test]
    fn preload_decision_skip_when_no_template_dir() {
        let cfg = crate::config::FreedomConfig::default();
        assert_eq!(preload_autorun_decision(&cfg), PreloadDecision::Skip);
    }

    #[test]
    fn preload_decision_warn_when_template_set_but_no_vault() {
        let mut cfg = crate::config::FreedomConfig::default();
        cfg.obsidian_preload_template_dir = Some("/tmp/template".to_string());
        assert_eq!(
            preload_autorun_decision(&cfg),
            PreloadDecision::WarnNoVault,
        );
    }

    #[test]
    fn preload_decision_run_when_both_set() {
        let mut cfg = crate::config::FreedomConfig::default();
        cfg.obsidian_preload_template_dir = Some("/tmp/template".to_string());
        cfg.obsidian_vault = Some("/tmp/vault".to_string());
        match preload_autorun_decision(&cfg) {
            PreloadDecision::Run {
                vault,
                template_dir,
                subdir,
            } => {
                assert_eq!(vault, PathBuf::from("/tmp/vault"));
                assert_eq!(template_dir, PathBuf::from("/tmp/template"));
                assert_eq!(subdir, PathBuf::new(), "unset subdir must be empty (manifest default)");
            }
            other => panic!("expected PreloadDecision::Run, got {other:?}"),
        }
    }

    #[test]
    fn preload_decision_run_uses_configured_subdir() {
        let mut cfg = crate::config::FreedomConfig::default();
        cfg.obsidian_preload_template_dir = Some("/tmp/template".to_string());
        cfg.obsidian_vault = Some("/tmp/vault".to_string());
        cfg.obsidian_preload_subdir = Some("MyPreload".to_string());
        match preload_autorun_decision(&cfg) {
            PreloadDecision::Run { subdir, .. } => {
                assert_eq!(subdir, PathBuf::from("MyPreload"));
            }
            other => panic!("expected PreloadDecision::Run, got {other:?}"),
        }
    }

    #[test]
    fn preload_state_path_for_distinct_for_different_roots() {
        let p1 = preload_state_path_for(Path::new("/tmp/root_a"));
        let p2 = preload_state_path_for(Path::new("/tmp/root_b"));
        assert_ne!(p1, p2, "distinct roots must map to distinct state paths");
    }

    #[test]
    fn preload_state_path_for_stable_for_same_root() {
        let path = Path::new("/tmp/template");
        assert_eq!(
            preload_state_path_for(path),
            preload_state_path_for(path),
            "same root must always produce the same state path",
        );
    }

    #[test]
    fn preload_state_path_for_has_json_extension() {
        let p = preload_state_path_for(Path::new("/some/path"));
        assert_eq!(
            p.extension().and_then(|s| s.to_str()),
            Some("json"),
            "state path must end with .json",
        );
    }

    #[test]
    fn knowledge_root_has_manifest_true_when_present() {
        let dir = tempdir().unwrap();
        write_preload_manifest(dir.path());
        assert!(
            knowledge_root_has_manifest(dir.path()),
            "must return true when preload_manifest.yaml exists",
        );
    }

    #[test]
    fn knowledge_root_has_manifest_false_when_missing() {
        let dir = tempdir().unwrap();
        assert!(
            !knowledge_root_has_manifest(dir.path()),
            "must return false when preload_manifest.yaml is absent",
        );
    }
}
