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
use crate::cli::obsidian_sync_util::{
    DirMtimeCache, WriteCoalescer, detect_sync_conflicts, obsidian_core_sync_enabled,
};
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
    /// Deliberate, consented offline mirror: fetch named remote sources from a
    /// YAML manifest and write them to a local directory with provenance
    /// frontmatter. SSRF-safe (https-only; private/loopback/link-local IPs
    /// blocked). No background fetch, no cron — one-shot operator command only.
    ///
    /// State is persisted to `<dest>/mirror_state.yaml` after each source so
    /// partial progress survives interruption. Re-run with unchanged upstream
    /// overwrites timestamps only (same content ⇒ same sha256 recorded).
    Mirror {
        /// YAML manifest listing sources to mirror.
        /// Accepts `offline_security_sources.yaml` shape directly:
        /// `id`/`primary_url`/`mirror_policy` are aliases for
        /// `name`/`url`/`policy`. Unknown extra fields are ignored.
        manifest: PathBuf,
        /// Destination directory. Defaults to `<manifest-dir>/mirrored/`.
        #[arg(long, value_name = "DIR")]
        dest: Option<PathBuf>,
        /// List what would be fetched; no network I/O.
        #[arg(long)]
        dry_run: bool,
        /// Skip the TTY consent prompt. Required for non-TTY / scripted use.
        #[arg(long)]
        yes: bool,
    },
    /// Promote a row from `idx_restricted` to `idx_groundtruth`.
    ///
    /// The row is stamped with `promoted_at` / `promoted_by` and an audit
    /// line is appended to `~/.neoth/promotion-audit.jsonl` (0600).
    /// Idempotent: promoting an already-promoted row is a no-op.
    Promote {
        /// Row id in `idx_restricted` to promote.
        id: i64,
        /// Describe what would happen without writing anything.
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
    pub blocked_sync_conflict: bool,
    pub conflict_files: usize,
    pub core_sync_enabled: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PreloadStats {
    pub files_considered: usize,
    pub files_copied: usize,
    pub skipped_identical: usize,
    pub skipped_dry_run: usize,
    pub skipped_policy: usize,
    /// Files whose write target canonicalized to a path outside the vault root
    /// (symlink/junction escape caught by the central containment guard).
    pub skipped_containment: usize,
    pub restricted_files: usize,
    pub ingest_candidates: usize,
    pub ingested_chunks: usize,
    pub restricted_ingested_chunks: usize,
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
            // GOLD-ADAPT-IGNIS-04: a standalone sync owns a collision-resistant
            // one-shot segment. This keeps the conflict guard audited without
            // racing a daemon that may own the primary segment.
            let wal_dir = crate::config::FreedomConfig::default_wal_dir();
            std::fs::create_dir_all(&wal_dir)
                .with_context(|| format!("create WAL directory {}", wal_dir.display()))?;
            let sequence =
                crate::time::now_unix_ns().saturating_add(u64::from(std::process::id()) << 12);
            let segment = wal_dir.join(format!("{sequence:020}-obsidian-sync.wal"));
            let (writer, join) = crate::wal::writer::spawn(segment)
                .context("spawn one-shot Obsidian sync WAL writer")?;
            let result = sync_archive(&root, &vault, &subdir, dry_run, Some(&writer)).await;
            drop(writer);
            join.await
                .context("join one-shot Obsidian sync WAL writer")?;
            let stats = result?;
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
        ObsidianAction::Promote { id, dry_run } => {
            let db_path = crate::memory::store::default_path();
            let audit_path =
                crate::config::FreedomConfig::default_neoth_home().join("promotion-audit.jsonl");
            let promoted_by = std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| "operator-cli".to_string());
            promote_cmd(id, dry_run, &db_path, &audit_path, &promoted_by)?;
        }
        ObsidianAction::Mirror {
            manifest,
            dest,
            dry_run,
            yes,
        } => {
            run_mirror(&manifest, dest.as_deref(), dry_run, yes).await?;
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
            println!(
                "{}",
                serde_json::to_string_pretty(&v).expect("wiki stats are infallible JSON")
            );
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

async fn append_obsidian_sync_gate_audit(
    wal: Option<&crate::wal::writer::WalWriterHandle>,
    conflict_count: Option<usize>,
    core_sync_enabled: Option<bool>,
    scan_complete: bool,
    reason: &'static str,
) -> Result<()> {
    let ts_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let payload = serde_json::to_vec(&serde_json::json!({
        "conflict_count": conflict_count,
        "core_sync_enabled": core_sync_enabled,
        "scan_complete": scan_complete,
        "reason": reason,
        "ts_unix": ts_unix,
    }))?;
    let header = crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_EXTENDED, &payload)
        .event_subtype(crate::wal::events::ExtendedSubtype::ObsidianSyncConflict as u8)
        .build();
    let writer =
        wal.context("Obsidian sync conflict detected but no durable WAL writer was provided")?;
    writer
        .append(header, payload)
        .await
        .context("append Obsidian sync conflict audit frame")?;
    Ok(())
}

pub async fn sync_archive(
    archive_root: &Path,
    vault: &Path,
    subdir: &Path,
    dry_run: bool,
    wal: Option<&crate::wal::writer::WalWriterHandle>,
) -> Result<SyncStats> {
    validate_subdir(subdir).with_context(|| {
        format!(
            "invalid sync subdir {}: must be a simple name, not a traversal path",
            subdir.display()
        )
    })?;

    // GOLD-ADAPT-IGNIS-04: detect both file-level collision markers and the
    // built-in Obsidian Sync plugin before writing. The audit append is part of
    // the gate: an unaudited conflict never degrades into a silent skip.
    {
        let conflict_report = match detect_sync_conflicts(vault) {
            Ok(report) => report,
            Err(scan_error) => {
                let audit =
                    append_obsidian_sync_gate_audit(wal, None, None, false, "marker_scan_failed")
                        .await;
                return match audit {
                    Ok(()) => Err(scan_error.context(
                        "Obsidian sync blocked because the conflict-marker scan was incomplete",
                    )),
                    Err(audit_error) => Err(scan_error.context(format!(
                        "Obsidian conflict-marker scan was incomplete and its audit failed: \
                         {audit_error:#}"
                    ))),
                };
            }
        };
        let conflict_files = conflict_report.conflicts.len();
        let core_sync_enabled = match obsidian_core_sync_enabled(vault) {
            Ok(enabled) => enabled,
            Err(core_error) => {
                let audit = append_obsidian_sync_gate_audit(
                    wal,
                    Some(conflict_files),
                    None,
                    true,
                    "core_sync_state_unknown",
                )
                .await;
                return match audit {
                    Ok(()) => Err(core_error.context(format!(
                        "inspect Obsidian core plugins in {}",
                        vault.display()
                    ))),
                    Err(audit_error) => Err(core_error.context(format!(
                        "Obsidian core-plugin state was unknown and its audit failed: \
                         {audit_error:#}"
                    ))),
                };
            }
        };
        if conflict_files > 0 || core_sync_enabled {
            if let Some(msg) = conflict_report.describe() {
                tracing::warn!(conflict_files, "{}", msg);
            }
            if core_sync_enabled {
                tracing::warn!(
                    "Obsidian's built-in Sync plugin is enabled; skipping NEOTH vault sync"
                );
            }
            let reason = match (conflict_files > 0, core_sync_enabled) {
                (true, true) => "conflict_files_and_core_sync",
                (true, false) => "conflict_files",
                (false, true) => "core_sync_enabled",
                (false, false) => unreachable!("guard only enters for a conflict"),
            };
            append_obsidian_sync_gate_audit(
                wal,
                Some(conflict_files),
                Some(core_sync_enabled),
                true,
                reason,
            )
            .await?;
            return Ok(SyncStats {
                blocked_sync_conflict: true,
                conflict_files,
                core_sync_enabled,
                ..SyncStats::default()
            });
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
#[cfg(test)]
pub(crate) fn preload_state_path_for(template: &Path) -> PathBuf {
    preload_state_path_for_home(
        &crate::config::FreedomConfig::default_neoth_home(),
        template,
    )
}

/// Instance-local variant used by `neoth serve --config <path>`.
pub(crate) fn preload_state_path_for_home(home: &Path, template: &Path) -> PathBuf {
    use std::hash::Hash;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    template.hash(&mut h);
    let key = std::hash::Hasher::finish(&h);
    home.join(format!("obsidian_preload_state_{key:016x}.json"))
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

/// Create `idx_preload_meta` if it does not exist.
///
/// Stores typed provenance columns — `rel_key` (source-file path), `scope`,
/// `content_hash`, `ingested_at`, and a backlink `groundtruth_id` — so
/// revocation and startup reconciliation can use parameterised SQL queries
/// instead of scanning statement text.
fn ensure_preload_meta_table(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS idx_preload_meta (
             id             INTEGER PRIMARY KEY,
             groundtruth_id INTEGER NOT NULL,
             rel_key        TEXT    NOT NULL,
             scope          TEXT    NOT NULL,
             content_hash   TEXT    NOT NULL,
             ingested_at    INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_preload_meta_lookup
             ON idx_preload_meta (rel_key, scope);",
    )
    .context("ensure idx_preload_meta")
}

/// Insert one provenance record for a just-written preload groundtruth chunk.
///
/// `rel_key` is the source-file path stored as a typed column, not embedded
/// in the statement string, so the next revocation pass can find it via SQL.
fn upsert_preload_meta(
    conn: &rusqlite::Connection,
    groundtruth_id: i64,
    rel_key: &str,
    scope: &str,
    content_hash: &str,
    ingested_at: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO idx_preload_meta \
             (groundtruth_id, rel_key, scope, content_hash, ingested_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![groundtruth_id, rel_key, scope, content_hash, ingested_at],
    )
    .context("upsert_preload_meta")?;
    Ok(())
}

/// Revoke all active groundtruth chunks for `(rel_key, scope)`.
///
/// Primary path: queries `idx_preload_meta` by structured columns — no
/// statement-text scanning.  Legacy fallback: for rows ingested before
/// `idx_preload_meta` shipped, falls back to the old text-marker scan so
/// existing vaults are not left with un-revokable orphan groundtruth rows.
fn revoke_preload_meta(
    conn: &rusqlite::Connection,
    scope: &str,
    rel_key: &str,
    now_ns: i64,
) -> Result<usize> {
    // Primary: structured lookup via typed columns.
    let ids: Vec<i64> = {
        let mut stmt = conn
            .prepare(
                "SELECT groundtruth_id FROM idx_preload_meta \
                 WHERE rel_key = ?1 AND scope = ?2",
            )
            .context("prepare idx_preload_meta lookup")?;
        stmt.query_map(rusqlite::params![rel_key, scope], |r| r.get(0))
            .context("query idx_preload_meta")?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("collect idx_preload_meta ids")?
    };

    let mut revoked = 0usize;
    for id in &ids {
        if crate::memory::groundtruth::revoke(conn, *id, now_ns)? {
            revoked += 1;
        }
    }

    // Remove meta rows — fresh ones will be inserted with the new groundtruth ids.
    conn.execute(
        "DELETE FROM idx_preload_meta WHERE rel_key = ?1 AND scope = ?2",
        rusqlite::params![rel_key, scope],
    )
    .context("delete stale idx_preload_meta rows")?;

    // Legacy fallback: text-marker scan for rows that pre-date idx_preload_meta.
    // Only triggered when the structured lookup found nothing.
    if ids.is_empty() {
        let marker = format!("source_path={rel_key} ");
        for row in crate::memory::groundtruth::list_for_scope(conn, scope)? {
            if row.statement.contains(&marker) {
                crate::memory::groundtruth::revoke(conn, row.id, now_ns)?;
                revoked += 1;
            }
        }
    }

    Ok(revoked)
}

/// Idempotent startup reconciliation: remove `idx_preload_meta` rows pointing
/// to groundtruth IDs that no longer exist or have been revoked.
///
/// The SAVEPOINT wrapping each file's update rolls back on a crash, so no
/// dangling meta rows are normally created.  This pass catches edge cases such
/// as an external revocation that left its meta backlink stale.
fn reconcile_preload_meta(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(
        "DELETE FROM idx_preload_meta \
         WHERE groundtruth_id NOT IN ( \
             SELECT id FROM idx_groundtruth WHERE revoked_at IS NULL \
         );",
    )
    .context("reconcile idx_preload_meta")
}

/// Open (or create+append) a 0600 audit log at `path`.
/// Same ACL pattern as `cli/cluster.rs open_audit_log`.
fn open_promotion_audit_log(path: &Path) -> Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open promotion audit log {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(windows)]
    {
        let _ = crate::wal::win_acl::restrict_to_owner(path);
    }
    Ok(file)
}

/// Drain all un-drained rows from `idx_promotion_outbox` to the JSONL audit
/// file, marking each row done only after a successful fsync.
///
/// Calling this at both the start and end of every `promote_cmd` invocation
/// covers two cases:
///   - **Normal path**: the just-inserted outbox row is written to JSONL.
///   - **Crash-recovery path**: rows left pending by a prior process death are
///     replayed before any new work begins.
///
/// If the table does not yet exist it is created (idempotent).  Empty outbox
/// is a no-op.
fn drain_promotion_outbox(conn: &rusqlite::Connection, audit_path: &Path) -> Result<()> {
    crate::memory::groundtruth::ensure_promotion_outbox(conn)?;
    let pending = crate::memory::groundtruth::pending_promotions(conn)?;
    if pending.is_empty() {
        return Ok(());
    }
    use std::io::Write;
    let mut f = open_promotion_audit_log(audit_path)?;
    let now_ns = crate::time::now_unix_ns_i64();
    for row in &pending {
        let record = serde_json::json!({
            "event": "restricted_promoted",
            "restricted_id": row.restricted_id,
            "groundtruth_id": row.groundtruth_id,
            "promoted_by": row.promoted_by,
            "promoted_at_ns": row.promoted_at_ns,
        });
        writeln!(f, "{record}").with_context(|| {
            format!("write promotion audit record (outbox_id={})", row.outbox_id)
        })?;
        f.flush()
            .with_context(|| format!("flush audit log (outbox_id={})", row.outbox_id))?;
        // fsync before marking done — the audit line must be on disk before
        // we lose the evidence of what to retry on next startup.
        f.sync_data()
            .with_context(|| format!("fsync audit log (outbox_id={})", row.outbox_id))?;
        crate::memory::groundtruth::mark_outbox_drained(conn, row.outbox_id, now_ns)
            .with_context(|| format!("mark outbox row {} drained", row.outbox_id))?;
    }
    Ok(())
}

/// Core of `neoth obsidian promote <id> [--dry-run]`.
///
/// Separated from `run_obsidian` so tests can inject the DB and audit paths
/// instead of relying on the real `~/.neoth/` home.
fn promote_cmd(
    id: i64,
    dry_run: bool,
    db_path: &Path,
    audit_path: &Path,
    promoted_by: &str,
) -> Result<()> {
    let conn = crate::memory::store::open(db_path).with_context(|| {
        format!(
            "open views.db for restricted promote ({})",
            db_path.display()
        )
    })?;
    // Replay any outbox rows left pending by a prior crash before doing new work.
    drain_promotion_outbox(&conn, audit_path)?;
    let now_ns = crate::time::now_unix_ns_i64();
    let outcome =
        crate::memory::groundtruth::promote_restricted(&conn, id, promoted_by, now_ns, dry_run)?;
    match &outcome {
        crate::memory::groundtruth::PromoteOutcome::Promoted { groundtruth_id } => {
            // Drain the just-inserted outbox row to JSONL.
            drain_promotion_outbox(&conn, audit_path)?;
            println!("promoted: restricted row {id} → groundtruth row {groundtruth_id}");
        }
        crate::memory::groundtruth::PromoteOutcome::AlreadyPromoted {
            groundtruth_id_hint,
        } => {
            println!(
                "already-promoted: restricted row {id} (groundtruth hint: {groundtruth_id_hint:?})"
            );
        }
        crate::memory::groundtruth::PromoteOutcome::DryRun { chunk } => {
            println!(
                "dry-run: would promote restricted row {id}: {:?}",
                chunk.statement
            );
        }
    }
    Ok(())
}

/// Central vault-containment guard applied to every preload write target.
///
/// Creates `parent` (fail-closed on mkdir failure), resolves its real path
/// via [`std::fs::canonicalize`], and verifies the result is a descendant of
/// `canonical_vault`.  Catches pre-existing symlinks and Windows junctions
/// anywhere in the destination tree — including those present between a prior
/// `validate_subdir` name-check and the actual write.
///
/// Called once per file from [`preload_template`] so ALL callers — the CLI
/// `Preload` arm, the daemon autorun primary template, `knowledge_preload_dirs`
/// entries, and manifest-derived subdirs — share this single centralized
/// boundary check.  Fail-closed: mkdir failure and canonicalize failure both
/// return `Err`.
fn assert_target_within_vault(canonical_vault: &Path, parent: &Path) -> Result<()> {
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create preload target dir {}", parent.display()))?;
    let real = std::fs::canonicalize(parent)
        .with_context(|| format!("canonicalize preload target {}", parent.display()))?;
    if !real.starts_with(canonical_vault) {
        anyhow::bail!(
            "preload write target resolves outside vault root \
             (symlink/junction escape detected); write refused (fail-closed)"
        );
    }
    Ok(())
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

    // Canonicalize the vault root once before the file loop so per-file
    // boundary checks operate on a stable baseline.  Vault creation is skipped
    // on dry-run (no writes happen there); on a real run, create_dir_all here
    // is idempotent with the later coalescer flush.
    let canonical_vault: Option<PathBuf> = if !dry_run {
        std::fs::create_dir_all(vault)
            .with_context(|| format!("create vault dir {}", vault.display()))?;
        Some(
            std::fs::canonicalize(vault)
                .with_context(|| format!("canonicalize vault root {}", vault.display()))?,
        )
    } else {
        None
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
    // Ensure the structured provenance index exists and is consistent before
    // writing any new data.  Must run before the file loop.
    if let Some(conn) = conn.as_ref() {
        ensure_preload_meta_table(conn).context("ensure idx_preload_meta on preload open")?;
        reconcile_preload_meta(conn).context("reconcile idx_preload_meta on preload open")?;
    }

    for file in &files {
        if file.policy.restricted {
            stats.restricted_files += 1;
        }
        let dst = vault.join(&effective_subdir).join(&file.rel);
        if dry_run {
            stats.skipped_dry_run += 1;
        } else {
            // Vault-containment guard: canonicalize the target's parent and
            // verify it resolves INSIDE the vault root.  Catches pre-existing
            // symlinks/junctions in the destination tree that could otherwise
            // redirect writes outside the vault — even when the subdir name
            // and the file's template-relative path are individually safe.
            // Fail-closed: skip the file on any error or boundary violation.
            let parent = dst.parent().unwrap_or(vault);
            if let Some(cv) = &canonical_vault {
                if let Err(e) = assert_target_within_vault(cv, parent) {
                    tracing::warn!(
                        file = %file.rel.display(),
                        error = %e,
                        "preload: skipping file — write target escapes vault boundary"
                    );
                    stats.skipped_containment += 1;
                    continue;
                }
            }
            coalescer.push(dst, file.bytes.clone());
            state
                .copied_hashes
                .insert(file.rel_key.clone(), file.hash.clone());
        }

        // RESTRICTED-GROUNDTRUTH-ISOLATION-01: a file with `policy.restricted = true`
        // must NEVER enter idx_groundtruth regardless of the `ingest` flag.
        // Restricted content routes exclusively through the `insert_restricted` branch
        // below.  Without this guard, setting both `ingest = true` and
        // `restricted = true` in a preload manifest caused the same chunk to be
        // written to BOTH tables — violating the "never to idx_groundtruth" comment
        // that precedes the restricted branch.
        if file.is_markdown && file.policy.ingest && !file.policy.restricted {
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
                    // SAVEPOINT: revoke-old + insert-new + meta-write are
                    // crash-atomic.  A mid-flight interrupt rolls back all
                    // three; next startup re-processes (state hash won't
                    // match → full re-ingest for this file).
                    conn.execute("SAVEPOINT preload_ingest", [])
                        .context("begin preload_ingest savepoint")?;
                    let ingest_result: Result<(usize, usize)> = (|| {
                        let revoked = revoke_preload_meta(conn, &scope, &file.rel_key, now_ns)?;
                        let mut inserted = 0usize;
                        for (heading, chunk) in &chunks {
                            let gt_id = crate::memory::groundtruth::insert(
                                conn,
                                &preload_statement(&file.rel_key, &file.policy, heading, chunk),
                                &crate::memory::groundtruth::Source::ImportObsidian,
                                &scope,
                                now_ns,
                            )?;
                            // Store provenance as typed fields (rel_key,
                            // content_hash, ingested_at) in idx_preload_meta —
                            // NOT re-parsed from the statement text on the next
                            // revocation pass.
                            upsert_preload_meta(
                                conn,
                                gt_id,
                                &file.rel_key,
                                &scope,
                                &file.hash,
                                now_ns,
                            )?;
                            inserted += 1;
                        }
                        Ok((revoked, inserted))
                    })();
                    match ingest_result {
                        Ok((revoked, inserted)) => {
                            conn.execute("RELEASE SAVEPOINT preload_ingest", [])
                                .context("release preload_ingest savepoint")?;
                            stats.revoked_chunks += revoked;
                            stats.ingested_chunks += inserted;
                        }
                        Err(e) => {
                            // Best-effort rollback — savepoint unwinds on
                            // connection close even if this fails.
                            let _ = conn.execute("ROLLBACK TO SAVEPOINT preload_ingest", []);
                            let _ = conn.execute("RELEASE SAVEPOINT preload_ingest", []);
                            return Err(e);
                        }
                    }
                }
                state
                    .ingested_hashes
                    .insert(file.rel_key.clone(), file.hash.clone());
            }
        }

        // L6-PRELOAD-RESTRICTED-INDEX-01 — restricted files (raw-source,
        // runtime-log, operational-security scope) route to `idx_restricted`,
        // never to `idx_groundtruth`.  `insert_restricted` is idempotent on
        // exact (statement, scope), so re-runs are safe without hash tracking.
        if file.is_markdown && file.policy.restricted && ingest && !dry_run {
            let markdown = String::from_utf8_lossy(&file.bytes);
            let chunks = markdown_chunks(&markdown, &file.policy.chunking);
            let scope = preload_scope(&file.policy);
            if let Some(conn) = conn.as_ref() {
                for (heading, chunk) in chunks {
                    crate::memory::groundtruth::insert_restricted(
                        conn,
                        &preload_statement(&file.rel_key, &file.policy, &heading, &chunk),
                        &file.rel_key,
                        &scope,
                        &file.policy.trust,
                        now_ns,
                    )?;
                    stats.restricted_ingested_chunks += 1;
                }
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
                serde_json::to_string_pretty(&stats)
                    .expect("Obsidian preload stats contain only serializable fields")
            );
        }
        OutputFormat::Table => {
            let mode = if stats.dry_run {
                "preload dry-run"
            } else {
                "preload"
            };
            println!(
                "obsidian {mode}: {} considered, {} copied, {} unchanged, {} dry-run, {} policy-skipped, {} containment-blocked, {} restricted ({} restricted-ingested), {} ingest-candidate, {} ingested chunk(s), {} revoked chunk(s)",
                stats.files_considered,
                stats.files_copied,
                stats.skipped_identical,
                stats.skipped_dry_run,
                stats.skipped_policy,
                stats.skipped_containment,
                stats.restricted_files,
                stats.restricted_ingested_chunks,
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
                "blocked_sync_conflict": stats.blocked_sync_conflict,
                "conflict_files": stats.conflict_files,
                "core_sync_enabled": stats.core_sync_enabled,
            });
            println!("{v}");
        }
        OutputFormat::Table => {
            if stats.blocked_sync_conflict {
                println!(
                    "obsidian sync: blocked ({} conflict file(s), built-in Sync {})",
                    stats.conflict_files,
                    if stats.core_sync_enabled {
                        "enabled"
                    } else {
                        "disabled"
                    },
                );
                return;
            }
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

// ── L6-PRELOAD-MIRROR-01 — offline mirror command ────────────────────────────
//
// `neoth obsidian mirror <manifest> [--dest <dir>] [--dry-run] [--yes]`
//
// One-shot deliberate offline mirror of named remote sources.
// Operator consent is required on TTY; `--yes` is required for scripted use.
// SSRF-safe: https-only, private/loopback/link-local IPs blocked on literal
// IP targets. The no-redirect HTTP client closes the post-validation gap where
// a public URL could otherwise 302 into a private address.

/// Maximum bytes accepted per mirrored file.
///
/// 8 MiB is generous for a README or wiki page and prevents runaway downloads
/// if the manifest accidentally points at a binary asset URL. Checked both via
/// the Content-Length response header (early-out for cooperative servers) and
/// by accumulating the streamed body (authoritative cap before disk write).
const MIRROR_SIZE_CAP: u64 = 8 * 1024 * 1024;

/// Top-level mirror manifest.
///
/// Only `sources` is required. All other top-level keys (version, catalog_id,
/// default_policy, risk_tiers, …) are tolerated so `offline_security_sources
/// .yaml` can be passed as-is without stripping its header fields.
#[derive(Debug, Deserialize)]
pub(crate) struct MirrorManifest {
    pub sources: Vec<MirrorSource>,
}

/// One source entry in the mirror manifest.
///
/// Core fields are `name` / `url` / `policy`. Aliases make the command accept
/// `offline_security_sources.yaml` unchanged: that catalog uses `id` for the
/// name, `primary_url` for the URL, and `mirror_policy` for the policy tag.
/// Unknown extra fields (risk_tier, notes, format, …) are silently ignored.
#[derive(Debug, Deserialize)]
pub(crate) struct MirrorSource {
    /// Unique slug — becomes the output filename stem.
    #[serde(alias = "id")]
    pub name: String,
    /// Remote URL to fetch. Must be `https://`.
    #[serde(alias = "primary_url")]
    pub url: String,
    /// Optional mirror policy tag. Recorded verbatim in state for operator
    /// review; not enforced by this command.
    #[serde(alias = "mirror_policy", default)]
    pub policy: Option<String>,
}

/// Per-source record persisted to `mirror_state.yaml`.
///
/// `error` is `Some` when the fetch failed. Re-running with unchanged upstream
/// overwrites `fetched_at` but keeps the same `sha256` (same content ⇒ same
/// hash ⇒ no logical change). `sha256` covers the raw fetched bytes before
/// the provenance frontmatter is prepended, so it can be verified against the
/// upstream source independently.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct MirrorSourceState {
    pub url: String,
    pub sha256: Option<String>,
    pub bytes: Option<u64>,
    /// Unix timestamp (seconds) of the last fetch attempt.
    pub fetched_at: Option<i64>,
    pub http_status: Option<u16>,
    /// Non-None when the fetch failed; stores the error message.
    pub error: Option<String>,
}

/// Full state persisted to `mirror_state.yaml`.
///
/// BTreeMap ensures deterministic ordering: same sources in any manifest
/// order produce the same YAML output.
type MirrorState = BTreeMap<String, MirrorSourceState>;

/// Validate `raw` as a mirror URL.
///
/// Rules enforced:
/// 1. Must parse as a valid URL.
/// 2. Scheme must be `https` (blocks `http://`, `file://`, custom schemes).
/// 3. If the host is a literal IP address, it must not be private, loopback,
///    link-local, CGNAT, broadcast, unspecified, or ULA.
///
/// Hostname-based targets whose DNS resolves to a private IP are NOT caught
/// here (no DNS resolution at validation time). [`guard_resolved_host`] closes
/// that gap by resolving the host and re-checking every A/AAAA against
/// [`block_mirror_ip`] immediately before the fetch. The no-redirect client
/// additionally prevents a public URL from 302-ing into a private address.
/// This matches the SSRF hardening applied in commit a44b6a3a
/// ("fix(security): block IPv4-mapped private IPs").
pub(crate) fn validate_mirror_url(raw: &str) -> Result<url::Url> {
    let url = url::Url::parse(raw).with_context(|| format!("invalid mirror URL: {raw}"))?;
    if url.scheme() != "https" {
        anyhow::bail!(
            "mirror URLs must use https (got scheme {:?}): {raw}",
            url.scheme()
        );
    }
    // Match url::Host directly — host_str() renders IPv6 with brackets
    // ("[::1]"), which IpAddr::parse rejects and would silently skip the guard.
    match url.host() {
        None => anyhow::bail!("mirror URL has no host: {raw}"),
        Some(url::Host::Ipv4(v4)) => {
            block_mirror_ip(std::net::IpAddr::V4(v4))
                .with_context(|| format!("SSRF guard rejected mirror URL: {raw}"))?;
        }
        Some(url::Host::Ipv6(v6)) => {
            block_mirror_ip(std::net::IpAddr::V6(v6))
                .with_context(|| format!("SSRF guard rejected mirror URL: {raw}"))?;
        }
        Some(url::Host::Domain(_)) => {}
    }
    Ok(url)
}

/// Reject IP addresses that the mirror command must never reach.
///
/// Covers loopback, private (RFC 1918), link-local (169.254.0.0/16 and
/// fe80::/10), CGNAT (100.64.0.0/10, RFC 6598), broadcast, unspecified,
/// ULA IPv6 (fc00::/7), and IPv4-mapped IPv6 aliases for all of the above.
fn block_mirror_ip(addr: std::net::IpAddr) -> Result<()> {
    match addr {
        std::net::IpAddr::V4(v4) => {
            if v4.is_loopback() {
                anyhow::bail!("blocked loopback address {v4}");
            }
            if v4.is_private() {
                anyhow::bail!("blocked private RFC-1918 address {v4}");
            }
            if v4.is_link_local() {
                anyhow::bail!("blocked link-local address {v4}");
            }
            if v4.is_broadcast() {
                anyhow::bail!("blocked broadcast address {v4}");
            }
            if v4.is_unspecified() {
                anyhow::bail!("blocked unspecified address {v4}");
            }
            // CGNAT 100.64.0.0/10 — not covered by is_private()
            let o = v4.octets();
            if o[0] == 100 && (o[1] & 0xC0) == 64 {
                anyhow::bail!("blocked CGNAT address {v4}");
            }
        }
        std::net::IpAddr::V6(v6) => {
            if v6.is_loopback() {
                anyhow::bail!("blocked loopback IPv6 {v6}");
            }
            if v6.is_unspecified() {
                anyhow::bail!("blocked unspecified IPv6 {v6}");
            }
            let segs = v6.segments();
            // ULA fc00::/7
            if (segs[0] & 0xFE00) == 0xFC00 {
                anyhow::bail!("blocked ULA IPv6 {v6}");
            }
            // link-local fe80::/10
            if (segs[0] & 0xFFC0) == 0xFE80 {
                anyhow::bail!("blocked link-local IPv6 {v6}");
            }
            // IPv4-mapped ::ffff:A.B.C.D — check the mapped address
            if let Some(v4) = v6.to_ipv4() {
                block_mirror_ip(std::net::IpAddr::V4(v4))
                    .with_context(|| format!("IPv4-mapped IPv6 {v6} aliases a blocked range"))?;
            }
        }
    }
    Ok(())
}

/// Resolve `url`'s host and reject if ANY resolved address is a blocked
/// (loopback/private/link-local/CGNAT/ULA/metadata) IP.
///
/// This closes the DNS-rebinding SSRF gap that [`validate_mirror_url`] cannot
/// see: a public hostname whose DNS points at a private address (e.g.
/// `metadata.google.internal` → `169.254.169.254`, or an attacker-controlled
/// `evil.example` → `127.0.0.1`). Literal-IP URLs are already vetted up front,
/// so this is a no-op for them.
///
/// Called immediately before the fetch to keep the resolve→connect window
/// minimal.
/// ponytail: resolve-then-connect still leaves a narrow TOCTOU window — DNS
/// could rebind to a private IP between this lookup and reqwest's own
/// resolution at connect. Full closure needs pinning the vetted IP via
/// `ClientBuilder::resolve(host, ip)` (not possible on the shared client used
/// here without a per-source client rebuild).
async fn guard_resolved_host(url: &url::Url) -> Result<()> {
    let host = match url.host() {
        Some(url::Host::Domain(h)) => h.to_string(),
        // Literal IPs are already vetted by validate_mirror_url.
        _ => return Ok(()),
    };
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
        .await
        .with_context(|| format!("resolve mirror host {host:?}"))?
        .collect();
    if addrs.is_empty() {
        anyhow::bail!("mirror host {host:?} resolved to no addresses");
    }
    for sa in addrs {
        block_mirror_ip(sa.ip()).with_context(|| {
            format!(
                "SSRF guard rejected resolved IP {} for mirror host {host:?}",
                sa.ip()
            )
        })?;
    }
    Ok(())
}

/// Load and parse a mirror manifest from `path`.
pub(crate) fn load_mirror_manifest(path: &Path) -> Result<MirrorManifest> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read mirror manifest {}", path.display()))?;
    serde_yaml::from_str(&body).with_context(|| format!("parse mirror manifest {}", path.display()))
}

fn load_mirror_state(path: &Path) -> Result<MirrorState> {
    if !path.exists() {
        return Ok(MirrorState::new());
    }
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read mirror state {}", path.display()))?;
    serde_yaml::from_str(&body).with_context(|| format!("parse mirror state {}", path.display()))
}

fn save_mirror_state(path: &Path, state: &MirrorState) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create mirror state dir {}", parent.display()))?;
    }
    let body = serde_yaml::to_string(state).context("serialize mirror state")?;
    std::fs::write(path, body.as_bytes())
        .with_context(|| format!("write mirror state {}", path.display()))
}

/// Hex-encoded SHA-256 of `data`.
///
/// Uses `sha2` (direct dep, version 0.10). The hash covers the raw fetched
/// bytes before the provenance frontmatter is prepended, enabling independent
/// verification against the upstream source.
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

/// Determine the output filename for a mirrored source.
///
/// Uses `.md` for URLs with no extension or with a `.md` extension; preserves
/// any other extension (`.yaml`, `.json`, `.txt`, …) so the file type is
/// self-evident without reading the content.
fn mirror_filename(name: &str, url: &url::Url) -> String {
    let ext = std::path::Path::new(url.path())
        .extension()
        .and_then(|e| e.to_str())
        .filter(|e| !e.is_empty() && *e != "md")
        .unwrap_or("md");
    format!("{name}.{ext}")
}

/// Prepend a YAML provenance frontmatter block to `content`.
///
/// The block records `source_url`, `fetched_at` (Unix seconds), `sha256`,
/// and `mirror_only: true`. The `mirror_only` flag signals to the preload
/// pipeline that this file must not be ingested into NEOTH recall — it is
/// copy-only provenance material (section trust = raw-source).
pub(crate) fn with_provenance_frontmatter(
    content: &str,
    url: &str,
    fetched_at: i64,
    sha256: &str,
) -> String {
    format!(
        "---\nsource_url: {url}\nfetched_at: {fetched_at}\nsha256: {sha256}\nmirror_only: true\n---\n\n{content}"
    )
}

/// Run `neoth obsidian mirror`.
///
/// Loads the manifest, validates all URLs (SSRF guard, no network), obtains
/// operator consent on TTY (unless `--yes`), then fetches each valid source
/// in manifest order. Per-source outcome is persisted to
/// `<dest>/mirror_state.yaml` after each fetch so partial progress survives
/// interruption. Exits non-zero only when ALL sources fail.
pub(crate) async fn run_mirror(
    manifest_path: &Path,
    dest: Option<&Path>,
    dry_run: bool,
    yes: bool,
) -> Result<()> {
    let manifest = load_mirror_manifest(manifest_path)?;
    if manifest.sources.is_empty() {
        println!("mirror: manifest has no sources — nothing to do.");
        return Ok(());
    }

    // Validate all URLs up-front (pure, zero network) and report every
    // SSRF rejection immediately so the operator sees the full picture before
    // any fetch begins.
    let mut valid: Vec<(&MirrorSource, url::Url)> = Vec::new();
    for src in &manifest.sources {
        match validate_mirror_url(&src.url) {
            Ok(u) => valid.push((src, u)),
            Err(e) => eprintln!("mirror: skipping {:?} — {e:#}", src.name),
        }
    }
    if valid.is_empty() {
        anyhow::bail!("mirror: no valid HTTPS sources found in manifest");
    }

    let manifest_dir = manifest_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let dest_dir = dest
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| manifest_dir.join("mirrored"));
    let state_path = dest_dir.join("mirror_state.yaml");

    // ── dry-run: list only, zero network I/O ─────────────────────────────
    if dry_run {
        println!(
            "[dry-run] would mirror {} source(s) → {}",
            valid.len(),
            dest_dir.display()
        );
        for (src, url) in &valid {
            let tag = src
                .policy
                .as_deref()
                .map(|p| format!("  [policy: {p}]"))
                .unwrap_or_default();
            println!("  {} — {}{tag}", src.name, url.as_str());
        }
        return Ok(());
    }

    // ── consent: required on TTY unless --yes ─────────────────────────────
    if !yes {
        use std::io::IsTerminal;
        if !std::io::stdin().is_terminal() {
            anyhow::bail!(
                "mirror: non-TTY stdin without --yes; refusing to fetch. \
                 Pass --yes to confirm fetch in scripted or piped use."
            );
        }
        println!(
            "mirror: about to fetch {} source(s) → {}",
            valid.len(),
            dest_dir.display()
        );
        for (src, url) in &valid {
            println!("  {} — {}", src.name, url.as_str());
        }
        {
            use std::io::Write;
            print!("Proceed? [y/N] ");
            std::io::stdout().flush().ok();
        }
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        if !matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("mirror: aborted.");
            return Ok(());
        }
    }

    // ── fetch ─────────────────────────────────────────────────────────────
    std::fs::create_dir_all(&dest_dir)
        .with_context(|| format!("create mirror dest {}", dest_dir.display()))?;

    // State is loaded once; new entries are merged and re-saved after each
    // source so partial progress is durable.
    let mut state = load_mirror_state(&state_path).unwrap_or_default();

    // No-redirect client: prevents a public URL from 302-ing into a private
    // address after the up-front validate_mirror_url check has passed.
    let client = crate::providers::http_client::build_client_no_redirect()
        .context("build HTTP client for mirror")?;

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mut any_ok = false;

    for (src, url) in &valid {
        let result = fetch_and_write_source(&client, src, url, &dest_dir, now_secs).await;
        match result {
            Ok(entry) => {
                any_ok = true;
                state.insert(src.name.clone(), entry);
            }
            Err(e) => {
                eprintln!("mirror: {} failed — {e:#}", src.name);
                state.insert(
                    src.name.clone(),
                    MirrorSourceState {
                        url: src.url.clone(),
                        fetched_at: Some(now_secs),
                        error: Some(format!("{e:#}")),
                        ..Default::default()
                    },
                );
            }
        }
        // Save state after every source so interrupts leave a consistent file.
        if let Err(e) = save_mirror_state(&state_path, &state) {
            eprintln!("mirror: warning — could not save state: {e:#}");
        }
    }

    if !any_ok {
        anyhow::bail!("mirror: all sources failed — see {}", state_path.display());
    }

    let ok_n = state.values().filter(|s| s.error.is_none()).count();
    let fail_n = state.values().filter(|s| s.error.is_some()).count();
    println!(
        "mirror: {ok_n}/{} source(s) fetched, {fail_n} failed — state: {}",
        valid.len(),
        state_path.display()
    );
    Ok(())
}

/// Fetch one source, write the file with provenance frontmatter, return state.
///
/// Errors are per-source: callers continue to the next source and record the
/// failure in `mirror_state.yaml`. Non-success HTTP status codes and exceeded
/// size caps are errors.
async fn fetch_and_write_source(
    client: &reqwest::Client,
    src: &MirrorSource,
    url: &url::Url,
    dest_dir: &Path,
    now_secs: i64,
) -> Result<MirrorSourceState> {
    // Re-check the resolved IP(s) immediately before connecting. validate_mirror_url
    // only vets literal-IP hosts; a hostname could resolve to a private address
    // (DNS-rebinding SSRF, e.g. metadata.google.internal → 169.254.169.254).
    guard_resolved_host(url).await?;

    let resp = client
        .get(url.as_str())
        .header("User-Agent", "neoth-mirror/1 (offline source pinning)")
        .send()
        .await
        .with_context(|| format!("GET {}", url.as_str()))?;

    let http_status = resp.status().as_u16();
    if !resp.status().is_success() {
        anyhow::bail!("HTTP {http_status}");
    }

    // Content-Length pre-check: cooperative servers get an early rejection.
    if let Some(cl) = resp.content_length() {
        if cl > MIRROR_SIZE_CAP {
            anyhow::bail!("Content-Length {cl} exceeds mirror size cap ({MIRROR_SIZE_CAP} bytes)");
        }
    }

    // Stream body via chunk() (no StreamExt import needed; reqwest `stream`
    // feature is enabled). Accumulate until the size cap; abort before writing
    // if the limit is reached mid-stream.
    let mut body: Vec<u8> = Vec::new();
    let mut resp = resp;
    while let Some(chunk) = resp
        .chunk()
        .await
        .with_context(|| format!("read body from {}", url.as_str()))?
    {
        if body.len() as u64 + chunk.len() as u64 > MIRROR_SIZE_CAP {
            anyhow::bail!(
                "response body exceeds mirror size cap ({MIRROR_SIZE_CAP} bytes); refusing to store"
            );
        }
        body.extend_from_slice(&chunk);
    }

    let bytes = body.len() as u64;
    // Hash the raw bytes before prepending the frontmatter so the stored sha256
    // is independently verifiable against the upstream source.
    let sha256 = sha256_hex(&body);
    let content = String::from_utf8_lossy(&body);
    let output = with_provenance_frontmatter(&content, url.as_str(), now_secs, &sha256);

    let filename = mirror_filename(&src.name, url);
    let out_path = dest_dir.join(&filename);
    std::fs::write(&out_path, output.as_bytes())
        .with_context(|| format!("write {}", out_path.display()))?;

    println!(
        "mirror:   {} → {} ({bytes}B sha256:{}…)",
        src.name,
        out_path.display(),
        &sha256[..16]
    );
    Ok(MirrorSourceState {
        url: src.url.clone(),
        sha256: Some(sha256),
        bytes: Some(bytes),
        fetched_at: Some(now_secs),
        http_status: Some(http_status),
        error: None,
    })
}

/// Shared test helper — used by `tests`, `mirror_tests`, and the
/// restricted-index tests, so it lives at module level (test builds only).
#[cfg(test)]
fn write_template_file(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
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
        let stats = sync_archive(
            &archive,
            &vault,
            &PathBuf::from("NEOTH-sessions"),
            false,
            None,
        )
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
        let _ = sync_archive(&archive, &vault, &subdir, false, None)
            .await
            .unwrap();
        let stats = sync_archive(&archive, &vault, &subdir, false, None)
            .await
            .unwrap();
        assert_eq!(stats.considered, 2);
        assert_eq!(stats.copied, 0, "second run must skip identical files");
        assert_eq!(stats.skipped_identical, 2);
    }

    #[tokio::test]
    async fn core_sync_plugin_blocks_copy_and_emits_durable_audit() {
        let dir = tempdir().unwrap();
        let archive = fake_archive(dir.path()).await;
        let vault = dir.path().join("vault");
        let obsidian = vault.join(".obsidian");
        std::fs::create_dir_all(&obsidian).unwrap();
        std::fs::write(obsidian.join("core-plugins.json"), br#"{"sync":true}"#).unwrap();

        let segment = dir.path().join("obsidian-conflict.wal");
        let (writer, join) = crate::wal::writer::spawn(segment.clone()).unwrap();
        let stats = sync_archive(
            &archive,
            &vault,
            &PathBuf::from("NEOTH-sessions"),
            false,
            Some(&writer),
        )
        .await
        .unwrap();
        drop(writer);
        join.await.unwrap();

        assert!(stats.blocked_sync_conflict);
        assert!(stats.core_sync_enabled);
        assert_eq!(stats.conflict_files, 0);
        assert!(!vault.join("NEOTH-sessions").exists());

        let bytes = std::fs::read(segment).unwrap();
        let segment_header = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
        let frame = crate::wal::frame::decode_frame(&bytes[segment_header.header_len()..]).unwrap();
        assert_eq!(
            frame.header.event_subtype,
            crate::wal::events::ExtendedSubtype::ObsidianSyncConflict as u8
        );
        let payload: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
        assert_eq!(payload["core_sync_enabled"], true);
        assert_eq!(payload["reason"], "core_sync_enabled");
    }

    #[tokio::test]
    async fn sync_conflict_without_wal_fails_closed() {
        let dir = tempdir().unwrap();
        let archive = fake_archive(dir.path()).await;
        let vault = dir.path().join("vault");
        let obsidian = vault.join(".obsidian");
        std::fs::create_dir_all(&obsidian).unwrap();
        std::fs::write(obsidian.join("core-plugins.json"), br#"["sync"]"#).unwrap();

        let error = sync_archive(
            &archive,
            &vault,
            &PathBuf::from("NEOTH-sessions"),
            false,
            None,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("no durable WAL writer"));
        assert!(!vault.join("NEOTH-sessions").exists());
    }

    #[tokio::test]
    async fn incomplete_conflict_scan_fails_closed_and_is_audited() {
        let dir = tempdir().unwrap();
        let archive = fake_archive(dir.path()).await;
        let vault_file = dir.path().join("not-a-vault-directory");
        std::fs::write(&vault_file, b"file where a vault directory was expected").unwrap();
        let segment = dir.path().join("obsidian-scan-failed.wal");
        let (writer, join) = crate::wal::writer::spawn(segment.clone()).unwrap();

        let error = sync_archive(
            &archive,
            &vault_file,
            &PathBuf::from("NEOTH-sessions"),
            false,
            Some(&writer),
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("conflict-marker scan was incomplete")
        );
        drop(writer);
        join.await.unwrap();

        let bytes = std::fs::read(segment).unwrap();
        let segment_header = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
        let frame = crate::wal::frame::decode_frame(&bytes[segment_header.header_len()..]).unwrap();
        assert_eq!(
            frame.header.event_subtype,
            crate::wal::events::ExtendedSubtype::ObsidianSyncConflict as u8
        );
        let payload: serde_json::Value = serde_json::from_slice(frame.payload).unwrap();
        assert_eq!(payload["reason"], "marker_scan_failed");
        assert_eq!(payload["scan_complete"], false);
        assert!(payload["conflict_count"].is_null());
    }

    #[tokio::test]
    async fn sync_recopies_when_source_changes() {
        let dir = tempdir().unwrap();
        let archive = fake_archive(dir.path()).await;
        let vault = dir.path().join("vault");
        let subdir = PathBuf::from("NEOTH-sessions");
        sync_archive(&archive, &vault, &subdir, false, None)
            .await
            .unwrap();

        // Mutate one source file — second sync must re-copy it.
        let src = archive.join("sessions/2026-05-14/093412-abc.md");
        tokio::fs::write(&src, "---\nsession: abc\nday: 2026-05-14\n---\n\nrewritten")
            .await
            .unwrap();
        let stats = sync_archive(&archive, &vault, &subdir, false, None)
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
        let stats = sync_archive(&archive, &vault, &subdir, true, None)
            .await
            .unwrap();
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
            None,
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
        let err = sync_archive(&archive, &vault, &PathBuf::from("../escape"), false, None)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid sync subdir"),
            "expected traversal rejection, got: {err}"
        );
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
        assert_eq!(preload_autorun_decision(&cfg), PreloadDecision::WarnNoVault,);
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
                assert_eq!(
                    subdir,
                    PathBuf::new(),
                    "unset subdir must be empty (manifest default)"
                );
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

    // ── NEOTH-AUDIT-PRELOAD-PROVENANCE-RECOVERY-01 ────────────────────────────

    /// (a) Structured-provenance round-trip: after a normal preload run,
    /// `idx_preload_meta` must contain typed columns (rel_key, scope,
    /// content_hash, ingested_at, groundtruth_id).  Revocation of the same
    /// file on a second run must proceed via a parameterised SQL lookup — not
    /// by text-scanning the statement.  Verified by checking that zero rows
    /// remain for the old groundtruth id after the second run.
    #[tokio::test]
    async fn preload_provenance_stored_as_structured_fields_not_text_parse() {
        let dir = tempdir().unwrap();
        let template = dir.path().join("template");
        let vault = dir.path().join("vault");
        let state = dir.path().join("state.json");
        let views_db = dir.path().join("views.db");
        write_preload_manifest(&template);
        write_template_file(&template, "wiki/a.md", "# Alpha\n\nBody one.");

        // First run: ingest.
        preload_template(
            &template,
            &vault,
            &std::path::PathBuf::from("NEOTH-Preload"),
            false,
            true,
            Some(&state),
            Some(&views_db),
        )
        .await
        .unwrap();

        let conn = crate::memory::store::open(&views_db).unwrap();

        // Verify structured provenance: idx_preload_meta has typed columns.
        let (gt_id, rel_key, scope, content_hash, ingested_at): (i64, String, String, String, i64) =
            conn.query_row(
                "SELECT groundtruth_id, rel_key, scope, content_hash, ingested_at \
                 FROM idx_preload_meta LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .expect("idx_preload_meta must have at least one row after ingest");

        assert_eq!(rel_key, "wiki/a.md", "rel_key stored as typed column");
        assert_eq!(
            scope, "neoth-preload:l6-wiki",
            "scope stored as typed column"
        );
        assert!(
            !content_hash.is_empty(),
            "content_hash stored as typed column"
        );
        assert!(ingested_at > 0, "ingested_at stored as typed column");
        assert!(gt_id > 0, "groundtruth_id references a real row");

        // Verify backlink: the groundtruth_id actually exists and is active.
        let gt_active: i64 = conn
            .query_row(
                "SELECT count(*) FROM idx_groundtruth \
                 WHERE id = ?1 AND revoked_at IS NULL",
                rusqlite::params![gt_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(gt_active, 1, "groundtruth row must be active");
        drop(conn);

        // Second run with changed content: the old chunk must be revoked via
        // the structured path (no text scanning).
        write_template_file(&template, "wiki/a.md", "# Alpha\n\nBody two (changed).");
        std::fs::remove_file(&state).unwrap(); // force re-ingest
        preload_template(
            &template,
            &vault,
            &std::path::PathBuf::from("NEOTH-Preload"),
            false,
            true,
            Some(&state),
            Some(&views_db),
        )
        .await
        .unwrap();

        let conn = crate::memory::store::open(&views_db).unwrap();
        // Old groundtruth_id must now be revoked.
        let old_active: i64 = conn
            .query_row(
                "SELECT count(*) FROM idx_groundtruth \
                 WHERE id = ?1 AND revoked_at IS NULL",
                rusqlite::params![gt_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            old_active, 0,
            "old chunk must be revoked after content change"
        );

        // Exactly one active chunk for the file after re-ingest (not double-indexed).
        let active_chunks: i64 = conn
            .query_row(
                "SELECT count(*) FROM idx_preload_meta \
                 WHERE rel_key = 'wiki/a.md' AND scope = 'neoth-preload:l6-wiki'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            active_chunks, 1,
            "exactly one active meta row after re-ingest"
        );
    }

    /// (b) Partial-write reconciliation: simulate a crash between SAVEPOINT
    /// revoke and RELEASE by manually revoking a groundtruth row and leaving
    /// its idx_preload_meta entry stale.  `reconcile_preload_meta` must remove
    /// the dangling row.  A subsequent preload run must re-ingest cleanly —
    /// exactly one active chunk, not double-indexed.
    #[tokio::test]
    async fn preload_reconciliation_removes_dangling_meta_and_reingest_is_idempotent() {
        let dir = tempdir().unwrap();
        let template = dir.path().join("template");
        let vault = dir.path().join("vault");
        let state = dir.path().join("state.json");
        let views_db = dir.path().join("views.db");
        write_preload_manifest(&template);
        write_template_file(&template, "wiki/a.md", "# Alpha\n\nBody one.");

        // Normal first run.
        preload_template(
            &template,
            &vault,
            &std::path::PathBuf::from("NEOTH-Preload"),
            false,
            true,
            Some(&state),
            Some(&views_db),
        )
        .await
        .unwrap();

        // Retrieve the groundtruth_id from the structured provenance index.
        let conn = crate::memory::store::open(&views_db).unwrap();
        let gt_id: i64 = conn
            .query_row(
                "SELECT groundtruth_id FROM idx_preload_meta \
                 WHERE rel_key = 'wiki/a.md' LIMIT 1",
                [],
                |r| r.get(0),
            )
            .expect("idx_preload_meta must have a row after ingest");

        // Simulate partial crash: revoke the groundtruth row but leave the
        // meta row pointing to it (as if the SAVEPOINT was rolled back after
        // the revoke but before the new insert, and the meta row was orphaned).
        crate::memory::groundtruth::revoke(&conn, gt_id, 9_000_000_000).unwrap();
        drop(conn);

        // Verify dangling meta row exists before reconciliation.
        let conn = crate::memory::store::open(&views_db).unwrap();
        let dangling: i64 = conn
            .query_row(
                "SELECT count(*) FROM idx_preload_meta WHERE groundtruth_id = ?1",
                rusqlite::params![gt_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            dangling, 1,
            "dangling meta row must exist before reconciliation"
        );

        // Run reconciliation directly (as preload_template would on next startup).
        reconcile_preload_meta(&conn).unwrap();

        let after: i64 = conn
            .query_row(
                "SELECT count(*) FROM idx_preload_meta WHERE groundtruth_id = ?1",
                rusqlite::params![gt_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(after, 0, "reconciliation must remove dangling meta row");
        drop(conn);

        // Next preload run must re-ingest cleanly: exactly one active chunk,
        // not double-indexed even though a revoked row exists.
        std::fs::remove_file(&state).unwrap(); // force re-ingest
        let stats = preload_template(
            &template,
            &vault,
            &std::path::PathBuf::from("NEOTH-Preload"),
            false,
            true,
            Some(&state),
            Some(&views_db),
        )
        .await
        .unwrap();
        assert!(
            stats.ingested_chunks >= 1,
            "must re-ingest after reconciliation"
        );

        let conn = crate::memory::store::open(&views_db).unwrap();
        let active: i64 = conn
            .query_row(
                "SELECT count(*) FROM idx_groundtruth \
                 WHERE scope = 'neoth-preload:l6-wiki' AND revoked_at IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            active, 1,
            "exactly one active groundtruth row — not double-indexed"
        );
    }

    // ── PRELOAD-CONTAINMENT-CENTRAL-01 ───────────────────────────────────────

    /// Platform-agnostic: a path that resolves outside the vault is refused;
    /// an in-vault nested path is accepted.
    ///
    /// `assert_target_within_vault` is called for every file target inside
    /// `preload_template`, so confirming the guard here proves the fix covers
    /// all callers: the CLI `Preload` arm, the autorun primary template,
    /// `knowledge_preload_dirs` entries, and manifest-derived subdirs.
    #[test]
    fn preload_containment_guard_rejects_outside_target_and_accepts_inside() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&vault).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let canonical_vault = std::fs::canonicalize(&vault).unwrap();

        // An in-vault nested path succeeds.
        let inside = vault.join("NEOTH-Preload").join("wiki");
        assert!(
            assert_target_within_vault(&canonical_vault, &inside).is_ok(),
            "in-vault target must be accepted"
        );

        // A path that physically resolves outside the vault is refused —
        // canonicalize(outside) will not start_with canonical_vault.
        let err = assert_target_within_vault(&canonical_vault, &outside);
        assert!(err.is_err(), "outside path must be rejected; got: {err:?}");
    }

    /// Unix-only: a symlink inside the vault pointing outside is refused by
    /// the containment guard — this is the primary symlink-escape vector.
    #[test]
    #[cfg(unix)]
    fn preload_containment_guard_rejects_symlink_escape_unix() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("vault");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&vault).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let canonical_vault = std::fs::canonicalize(&vault).unwrap();

        // Symlink inside the vault that resolves to a directory outside it.
        let evil_link = vault.join("evil");
        std::os::unix::fs::symlink(&outside, &evil_link).unwrap();

        let err = assert_target_within_vault(&canonical_vault, &evil_link);
        assert!(err.is_err(), "symlink escape must be refused: {err:?}");
    }
}

// ── L6-PRELOAD-MIRROR-01 tests ────────────────────────────────────────────────
#[cfg(test)]
mod mirror_tests {
    use super::*;
    use tempfile::tempdir;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn write_manifest(dir: &std::path::Path, yaml: &str) -> std::path::PathBuf {
        let p = dir.join("mirror.yaml");
        std::fs::write(&p, yaml).unwrap();
        p
    }

    // ── SSRF guard — literal IP rejections ───────────────────────────────────

    #[test]
    fn ssrf_rejects_loopback_127_0_0_1() {
        let e = validate_mirror_url("https://127.0.0.1/readme.md").unwrap_err();
        let msg = format!("{e:#}");
        assert!(
            msg.contains("loopback") || msg.contains("SSRF"),
            "expected loopback/SSRF message, got: {msg}"
        );
    }

    #[test]
    fn ssrf_rejects_private_10_x() {
        let e = validate_mirror_url("https://10.0.0.1/readme.md").unwrap_err();
        let msg = format!("{e:#}");
        assert!(
            msg.contains("private") || msg.contains("SSRF"),
            "got: {msg}"
        );
    }

    #[test]
    fn ssrf_rejects_private_192_168_x() {
        let e = validate_mirror_url("https://192.168.1.100/readme.md").unwrap_err();
        let msg = format!("{e:#}");
        assert!(
            msg.contains("private") || msg.contains("SSRF"),
            "got: {msg}"
        );
    }

    #[test]
    fn ssrf_rejects_link_local_169_254() {
        // AWS/GCP metadata endpoint
        let e = validate_mirror_url("https://169.254.169.254/latest/meta-data/").unwrap_err();
        let msg = format!("{e:#}");
        assert!(
            msg.contains("link-local") || msg.contains("SSRF"),
            "got: {msg}"
        );
    }

    #[test]
    fn ssrf_rejects_file_scheme() {
        let e = validate_mirror_url("file:///etc/passwd").unwrap_err();
        assert!(
            format!("{e:#}").contains("https"),
            "file:// should be rejected for wrong scheme"
        );
    }

    #[test]
    fn ssrf_rejects_plain_http() {
        let e = validate_mirror_url("http://example.com/readme.md").unwrap_err();
        assert!(format!("{e:#}").contains("https"));
    }

    #[test]
    fn ssrf_rejects_ipv4_mapped_private_v6() {
        // ::ffff:10.0.0.1 aliases RFC-1918
        let e = validate_mirror_url("https://[::ffff:10.0.0.1]/readme.md").unwrap_err();
        let msg = format!("{e:#}");
        assert!(
            msg.contains("SSRF") || msg.contains("private") || msg.contains("IPv4"),
            "got: {msg}"
        );
    }

    #[test]
    fn ssrf_rejects_ipv6_loopback() {
        let e = validate_mirror_url("https://[::1]/readme.md").unwrap_err();
        let msg = format!("{e:#}");
        assert!(
            msg.contains("loopback") || msg.contains("SSRF"),
            "got: {msg}"
        );
    }

    #[test]
    fn ssrf_rejects_ula_ipv6() {
        let e = validate_mirror_url("https://[fc00::1]/readme.md").unwrap_err();
        let msg = format!("{e:#}");
        assert!(msg.contains("ULA") || msg.contains("SSRF"), "got: {msg}");
    }

    #[test]
    fn ssrf_rejects_link_local_ipv6_fe80() {
        let e = validate_mirror_url("https://[fe80::1]/readme.md").unwrap_err();
        let msg = format!("{e:#}");
        assert!(
            msg.contains("link-local") || msg.contains("SSRF"),
            "got: {msg}"
        );
    }

    #[test]
    fn ssrf_accepts_public_hostname() {
        let result =
            validate_mirror_url("https://raw.githubusercontent.com/foo/bar/main/README.md");
        assert!(result.is_ok(), "public hostname must pass: {result:?}");
    }

    #[tokio::test]
    async fn ssrf_guard_rejects_hostname_resolving_to_loopback() {
        // `localhost` resolves to 127.0.0.1 / ::1 through the system resolver
        // (hosts file — no network needed). validate_mirror_url passes it (the
        // Domain arm is a no-op), but guard_resolved_host must reject it once
        // it sees the resolved loopback address. This is the DNS-rebinding case.
        let url = validate_mirror_url("https://localhost/readme.md")
            .expect("localhost passes literal-IP validation");
        let e = guard_resolved_host(&url)
            .await
            .expect_err("loopback-resolving host must be rejected");
        let msg = format!("{e:#}");
        assert!(
            msg.contains("loopback") || msg.contains("SSRF"),
            "got: {msg}"
        );
    }

    #[tokio::test]
    async fn ssrf_guard_noop_for_literal_public_ip_free_path() {
        // A literal-IP URL never reaches the resolver arm (already vetted by
        // validate_mirror_url), so the guard is a no-op that returns Ok even
        // offline. Use a documentation-range IP to avoid any real connect.
        let url = url::Url::parse("https://203.0.113.7/readme.md").unwrap();
        assert!(guard_resolved_host(&url).await.is_ok());
    }

    // ── Manifest parse — name/url/policy fields ───────────────────────────────

    #[test]
    fn manifest_parses_name_url_policy() {
        let dir = tempdir().unwrap();
        let p = write_manifest(
            dir.path(),
            "sources:\n  - name: example\n    url: \"https://example.com/README.md\"\n    policy: full-mirror-ok\n",
        );
        let m = load_mirror_manifest(&p).unwrap();
        assert_eq!(m.sources.len(), 1);
        assert_eq!(m.sources[0].name, "example");
        assert_eq!(m.sources[0].url, "https://example.com/README.md");
        assert_eq!(m.sources[0].policy.as_deref(), Some("full-mirror-ok"));
    }

    #[test]
    fn manifest_accepts_id_primary_url_mirror_policy_aliases() {
        // Directly loadable from offline_security_sources.yaml without modification.
        let yaml = concat!(
            "version: 1\ncatalog_id: test\n",
            "sources:\n",
            "  - id: hacktricks\n",
            "    title: \"HackTricks\"\n",
            "    primary_url: \"https://github.com/HackTricks-wiki/hacktricks\"\n",
            "    mirror_policy: full-mirror-ok\n",
            "    risk_tier: dual-use-payloads\n",
            "    offline_priority: 1\n",
            "    notes: \"broad pentest corpus\"\n",
        );
        let dir = tempdir().unwrap();
        let p = write_manifest(dir.path(), yaml);
        let m = load_mirror_manifest(&p).unwrap();
        assert_eq!(m.sources.len(), 1);
        assert_eq!(m.sources[0].name, "hacktricks");
        assert_eq!(
            m.sources[0].url,
            "https://github.com/HackTricks-wiki/hacktricks"
        );
        assert_eq!(m.sources[0].policy.as_deref(), Some("full-mirror-ok"));
    }

    #[test]
    fn manifest_tolerates_extra_top_level_fields() {
        // default_policy, risk_tiers, and other catalog-level keys must not fail parse.
        let yaml = concat!(
            "version: 1\ncatalog_id: extra-fields-test\n",
            "default_policy:\n  copy_to_vault: true\n",
            "risk_tiers:\n  safe-reference:\n    description: \"safe\"\n",
            "sources:\n",
            "  - name: src\n",
            "    url: \"https://example.com/README.md\"\n",
            "    risk_tier: safe-reference\n",
            "    format: [\"markdown\"]\n",
            "    notes: \"just a test\"\n",
        );
        let dir = tempdir().unwrap();
        let p = write_manifest(dir.path(), yaml);
        let m = load_mirror_manifest(&p).unwrap();
        assert_eq!(m.sources.len(), 1);
        assert_eq!(m.sources[0].name, "src");
    }

    #[test]
    fn manifest_policy_field_is_optional() {
        let yaml = "sources:\n  - name: no-policy\n    url: \"https://example.com/README.md\"\n";
        let dir = tempdir().unwrap();
        let p = write_manifest(dir.path(), yaml);
        let m = load_mirror_manifest(&p).unwrap();
        assert!(m.sources[0].policy.is_none());
    }

    // ── dry-run: zero network I/O, zero files created ─────────────────────────

    #[tokio::test]
    async fn dry_run_creates_no_files_and_no_state() {
        let dir = tempdir().unwrap();
        let p = write_manifest(
            dir.path(),
            "sources:\n  - name: test-src\n    url: \"https://raw.githubusercontent.com/example/repo/main/README.md\"\n",
        );
        let dest = dir.path().join("mirrored");
        run_mirror(&p, Some(&dest), /*dry_run=*/ true, /*yes=*/ true)
            .await
            .unwrap();
        assert!(!dest.exists(), "dry-run must not create dest dir");
    }

    #[tokio::test]
    async fn dry_run_with_invalid_url_also_produces_no_files() {
        let dir = tempdir().unwrap();
        // SSRF-rejected URL: dry-run should still succeed (zero-fetch) but skip it
        let p = write_manifest(
            dir.path(),
            "sources:\n  - name: bad\n    url: \"https://127.0.0.1/README.md\"\n",
        );
        let dest = dir.path().join("mirrored");
        // run_mirror returns Err when all sources are invalid — that's expected here
        let _ = run_mirror(&p, Some(&dest), true, true).await;
        assert!(
            !dest.exists(),
            "dry-run must not create dest dir even with invalid URLs"
        );
    }

    // ── per-source failure continues; nonzero exit only when ALL fail ─────────

    #[test]
    fn failed_source_state_records_error_and_clears_hash() {
        let s = MirrorSourceState {
            url: "https://example.com".to_string(),
            error: Some("HTTP 404".to_string()),
            fetched_at: Some(1_720_000_000),
            ..Default::default()
        };
        assert!(s.error.is_some(), "failed entry must carry error");
        assert!(s.sha256.is_none(), "failed entry must not have sha256");
        assert!(s.bytes.is_none(), "failed entry must not have bytes");
        assert!(
            s.http_status.is_none(),
            "failed entry must not have http_status"
        );
    }

    // ── SHA-256 correctness & determinism ─────────────────────────────────────

    #[test]
    fn sha256_hex_is_deterministic() {
        assert_eq!(sha256_hex(b"neoth mirror"), sha256_hex(b"neoth mirror"));
    }

    #[test]
    fn sha256_hex_is_64_chars() {
        assert_eq!(
            sha256_hex(b"anything").len(),
            64,
            "sha256 hex must be 64 chars"
        );
    }

    #[test]
    fn sha256_hex_differs_for_different_content() {
        assert_ne!(sha256_hex(b"content A"), sha256_hex(b"content B"));
    }

    #[test]
    fn sha256_known_empty_vector() {
        // FIPS 180-4 test vector for SHA-256("")
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_known_abc_vector() {
        // FIPS 180-4 test vector for SHA-256("abc") — 64 hex chars (32 bytes).
        // Last byte is 0x02, which hex-encodes as "02" not "2".
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    // ── provenance frontmatter ────────────────────────────────────────────────

    #[test]
    fn provenance_frontmatter_has_all_required_fields() {
        let result = with_provenance_frontmatter(
            "# README content",
            "https://example.com/README.md",
            1_720_000_000,
            "abc123def456",
        );
        assert!(
            result.starts_with("---\n"),
            "must start with YAML frontmatter fence"
        );
        assert!(result.contains("source_url: https://example.com/README.md"));
        assert!(result.contains("fetched_at: 1720000000"));
        assert!(result.contains("sha256: abc123def456"));
        assert!(result.contains("mirror_only: true"));
        assert!(
            result.contains("# README content"),
            "original content must be preserved"
        );
    }

    #[test]
    fn provenance_frontmatter_original_content_follows_separator() {
        let body = "# Title\n\nSome text.";
        let result = with_provenance_frontmatter(body, "https://x.example/r.md", 0, "h");
        // Frontmatter block must be closed with ---
        assert!(
            result.contains("---\n\n"),
            "frontmatter must be closed with ---"
        );
        assert!(result.ends_with("Some text."));
    }

    // ── output filename derivation ────────────────────────────────────────────

    #[test]
    fn mirror_filename_defaults_to_md_for_extensionless_path() {
        let url = url::Url::parse("https://example.com/some/path").unwrap();
        assert_eq!(mirror_filename("owasp-wstg", &url), "owasp-wstg.md");
    }

    #[test]
    fn mirror_filename_uses_md_for_md_url() {
        let url = url::Url::parse("https://example.com/README.md").unwrap();
        assert_eq!(mirror_filename("hacktricks", &url), "hacktricks.md");
    }

    #[test]
    fn mirror_filename_preserves_yaml_extension() {
        let url = url::Url::parse("https://example.com/data.yaml").unwrap();
        assert_eq!(mirror_filename("lolbas", &url), "lolbas.yaml");
    }

    #[test]
    fn mirror_filename_preserves_json_extension() {
        let url = url::Url::parse("https://example.com/attack.json").unwrap();
        assert_eq!(mirror_filename("mitre-attack", &url), "mitre-attack.json");
    }

    // ── size cap constant ─────────────────────────────────────────────────────

    #[test]
    fn size_cap_is_8_mib() {
        assert_eq!(
            MIRROR_SIZE_CAP,
            8 * 1024 * 1024,
            "size cap must be exactly 8 MiB"
        );
    }

    // ── mirror_state.yaml round-trip ──────────────────────────────────────────

    #[test]
    fn mirror_state_round_trips_through_yaml() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mirror_state.yaml");
        let mut state = MirrorState::new();
        state.insert(
            "example".to_string(),
            MirrorSourceState {
                url: "https://example.com/README.md".to_string(),
                sha256: Some("abc123deadbeef".to_string()),
                bytes: Some(4096),
                fetched_at: Some(1_720_000_000),
                http_status: Some(200),
                error: None,
            },
        );
        save_mirror_state(&path, &state).unwrap();
        let loaded = load_mirror_state(&path).unwrap();
        let entry = loaded
            .get("example")
            .expect("entry must survive round-trip");
        assert_eq!(entry.sha256.as_deref(), Some("abc123deadbeef"));
        assert_eq!(entry.bytes, Some(4096));
        assert_eq!(entry.http_status, Some(200));
        assert!(entry.error.is_none());
        assert_eq!(entry.fetched_at, Some(1_720_000_000));
    }

    #[test]
    fn mirror_state_btreemap_ordering_is_deterministic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.yaml");
        let mut s = MirrorState::new();
        // Insert in reverse alphabetical order
        for name in ["zebra", "alpha", "middle"] {
            s.insert(
                name.to_string(),
                MirrorSourceState {
                    url: "https://x.example".to_string(),
                    ..Default::default()
                },
            );
        }
        save_mirror_state(&path, &s).unwrap();
        let yaml = std::fs::read_to_string(&path).unwrap();
        let alpha_pos = yaml.find("alpha").unwrap();
        let middle_pos = yaml.find("middle").unwrap();
        let zebra_pos = yaml.find("zebra").unwrap();
        assert!(
            alpha_pos < middle_pos,
            "BTreeMap must output alpha before middle"
        );
        assert!(
            middle_pos < zebra_pos,
            "BTreeMap must output middle before zebra"
        );
    }

    // ── wiremock-style success: file written with correct sha256 ──────────────
    // (Real network calls are excluded per BSOD constraint. This test drives
    //  the pure helper layer — sha256_hex + with_provenance_frontmatter +
    //  mirror_filename — end-to-end the same path fetch_and_write_source would
    //  take, verifying the file+state contract without network I/O.)

    #[test]
    fn successful_fetch_contract_file_and_state_have_matching_sha256() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();

        let raw_content = b"# HackTricks README\n\nSome content here.\n";
        let sha256 = sha256_hex(raw_content);
        let url_str = "https://github.com/HackTricks-wiki/hacktricks";
        let fetched_at: i64 = 1_720_000_000;

        // Simulate what fetch_and_write_source does after getting the body
        let content = String::from_utf8_lossy(raw_content);
        let output = with_provenance_frontmatter(&content, url_str, fetched_at, &sha256);
        let url = url::Url::parse(url_str).unwrap();
        let filename = mirror_filename("hacktricks", &url);
        let out_path = dest.join(&filename);
        std::fs::write(&out_path, output.as_bytes()).unwrap();

        // File must exist
        assert!(out_path.exists(), "output file must be written");

        // File must start with frontmatter containing the sha256
        let written = std::fs::read_to_string(&out_path).unwrap();
        assert!(
            written.contains(&sha256),
            "file must contain the sha256 of raw content"
        );
        assert!(
            written.contains("mirror_only: true"),
            "file must have mirror_only flag"
        );

        // State record must carry the same sha256
        let state_entry = MirrorSourceState {
            url: url_str.to_string(),
            sha256: Some(sha256.clone()),
            bytes: Some(raw_content.len() as u64),
            fetched_at: Some(fetched_at),
            http_status: Some(200),
            error: None,
        };
        assert_eq!(state_entry.sha256.as_deref(), Some(sha256.as_str()));
        assert!(state_entry.error.is_none());
    }

    // ── L6-PRELOAD-RESTRICTED-INDEX-01 tests ─────────────────────────────

    /// Manifest helper that adds a restricted section with real chunking.
    /// `scope: offline-security-restricted` + `trust: dual-use-payloads`
    /// → `policy.restricted = true`, `policy.ingest = false`.
    fn write_preload_manifest_with_restricted(root: &Path) {
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
  - path: restricted
    scope: offline-security-restricted
    trust: dual-use-payloads
    ingest: false
    copy_to_vault: true
    chunking: markdown-heading
"#,
        );
    }

    /// Curated markdown → `idx_groundtruth`.
    /// Restricted markdown → `idx_restricted`.
    /// Restricted rows are invisible to normal recall (surface_for_recall /
    /// list_for_scope) but visible via `search_restricted`.
    #[tokio::test]
    async fn preload_routes_curated_to_groundtruth_and_restricted_to_idx_restricted() {
        let dir = tempdir().unwrap();
        let template = dir.path().join("template");
        let vault = dir.path().join("vault");
        let state = dir.path().join("state.json");
        let views_db = dir.path().join("views.db");

        write_preload_manifest_with_restricted(&template);
        write_template_file(&template, "wiki/safe.md", "# Safe\n\nCurated body");
        write_template_file(
            &template,
            "restricted/payload.md",
            "# Exploit\n\nRestricted payload details",
        );

        let stats = preload_template(
            &template,
            &vault,
            &std::path::PathBuf::from("NEOTH-Preload"),
            false,
            true,
            Some(&state),
            Some(&views_db),
        )
        .await
        .unwrap();

        assert_eq!(stats.ingest_candidates, 1, "only curated wiki/safe.md");
        assert_eq!(stats.ingested_chunks, 1, "one curated chunk");
        assert_eq!(stats.restricted_files, 1, "restricted/payload.md counted");
        assert_eq!(
            stats.restricted_ingested_chunks, 1,
            "one restricted chunk in idx_restricted"
        );

        let conn = crate::memory::store::open(&views_db).unwrap();

        // Curated lands in idx_groundtruth.
        let gt_rows =
            crate::memory::groundtruth::list_for_scope(&conn, "neoth-preload:l6-wiki").unwrap();
        assert_eq!(gt_rows.len(), 1);
        assert!(gt_rows[0].statement.contains("Curated body"));

        // Restricted NOT in idx_groundtruth.
        let gt_all = crate::memory::groundtruth::list_for_scope(
            &conn,
            "neoth-preload:offline-security-restricted",
        )
        .unwrap();
        assert!(
            gt_all.is_empty(),
            "restricted scope must not appear in idx_groundtruth"
        );

        // Restricted IS in idx_restricted via search_restricted.
        let restricted_rows = crate::memory::groundtruth::search_restricted(
            &conn,
            "neoth-preload:offline-security-restricted",
        )
        .unwrap();
        assert_eq!(restricted_rows.len(), 1);
        assert!(
            restricted_rows[0]
                .statement
                .contains("Restricted payload details")
        );
        assert_eq!(restricted_rows[0].risk_tier, "dual-use-payloads");
        assert!(restricted_rows[0].promoted_at.is_none(), "not yet promoted");
    }

    /// Second preload run is idempotent — `insert_restricted` deduplicates on
    /// exact `(statement, scope)` so the count stays at 1.
    #[tokio::test]
    async fn preload_restricted_ingest_is_idempotent_on_rerun() {
        let dir = tempdir().unwrap();
        let template = dir.path().join("template");
        let vault = dir.path().join("vault");
        let state = dir.path().join("state.json");
        let views_db = dir.path().join("views.db");

        write_preload_manifest_with_restricted(&template);
        write_template_file(
            &template,
            "restricted/payload.md",
            "# Exploit\n\nSame content",
        );

        for _ in 0..2 {
            preload_template(
                &template,
                &vault,
                &std::path::PathBuf::from("NEOTH-Preload"),
                false,
                true,
                Some(&state),
                Some(&views_db),
            )
            .await
            .unwrap();
        }

        let conn = crate::memory::store::open(&views_db).unwrap();
        let rows = crate::memory::groundtruth::search_restricted(
            &conn,
            "neoth-preload:offline-security-restricted",
        )
        .unwrap();
        assert_eq!(rows.len(), 1, "idempotent — no duplicate restricted rows");
    }

    /// `promote_cmd` round-trip: promotes a restricted row, writes audit JSON,
    /// second call is no-op, dry-run writes nothing.
    #[test]
    fn promote_cmd_round_trip_writes_audit_and_is_idempotent() {
        let dir = tempdir().unwrap();
        let views_db = dir.path().join("views.db");
        let audit_path = dir.path().join("promotion-audit.jsonl");

        // Seed one restricted row.
        let conn = crate::memory::store::open(&views_db).unwrap();
        let now_ns = crate::time::now_unix_ns_i64();
        let restricted_id = crate::memory::groundtruth::insert_restricted(
            &conn,
            "test payload statement",
            "test-source",
            "neoth-preload:offline-security-restricted",
            "dual-use-payloads",
            now_ns,
        )
        .unwrap();
        drop(conn);

        // First promote — must succeed and write audit line.
        promote_cmd(
            restricted_id,
            false,
            &views_db,
            &audit_path,
            "test-operator",
        )
        .unwrap();
        assert!(audit_path.exists(), "audit file must be created");
        let audit_content = std::fs::read_to_string(&audit_path).unwrap();
        assert!(
            audit_content.contains("restricted_promoted"),
            "audit must contain event type"
        );
        assert!(
            audit_content.contains(&restricted_id.to_string()),
            "audit must contain the restricted_id"
        );
        assert!(
            audit_content.contains("test-operator"),
            "audit must record promoted_by"
        );

        // Second promote — no-op (AlreadyPromoted), audit file unchanged length.
        let len_before = std::fs::metadata(&audit_path).unwrap().len();
        promote_cmd(
            restricted_id,
            false,
            &views_db,
            &audit_path,
            "test-operator",
        )
        .unwrap();
        let len_after = std::fs::metadata(&audit_path).unwrap().len();
        assert_eq!(
            len_before, len_after,
            "second promote must not write to audit"
        );

        // Dry-run on a fresh restricted row — audit untouched.
        let conn2 = crate::memory::store::open(&views_db).unwrap();
        let id2 = crate::memory::groundtruth::insert_restricted(
            &conn2,
            "another payload",
            "test-source",
            "neoth-preload:offline-security-restricted",
            "dual-use-payloads",
            now_ns,
        )
        .unwrap();
        drop(conn2);
        let len_before_dry = std::fs::metadata(&audit_path).unwrap().len();
        promote_cmd(id2, true, &views_db, &audit_path, "test-operator").unwrap();
        let len_after_dry = std::fs::metadata(&audit_path).unwrap().len();
        assert_eq!(
            len_before_dry, len_after_dry,
            "dry-run must not write to audit"
        );
        // Verify the row was not actually promoted.
        let conn3 = crate::memory::store::open(&views_db).unwrap();
        let chunk = crate::memory::groundtruth::get_restricted(&conn3, id2)
            .unwrap()
            .unwrap();
        assert!(
            chunk.promoted_at.is_none(),
            "dry-run must not stamp promoted_at"
        );
    }
}
