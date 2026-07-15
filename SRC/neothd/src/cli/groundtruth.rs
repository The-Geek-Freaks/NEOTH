//! `neoth groundtruth` — manage hard-stored facts. Phase 28c R-24 GT-9.
//!
//! Subcommands map 1:1 onto `memory::groundtruth` CRUD calls:
//!   `list`    — list active rows, optionally filtered by scope
//!   `add`     — insert a new statement
//!   `revoke`  — mark a row revoked by id
//!
//! All paths open `views.db` directly; the daemon need not be running.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use tracing::info;

use crate::cli::OutputFormat;
use crate::memory::{groundtruth, store};

#[derive(Args, Debug, Clone)]
pub struct GroundtruthArgs {
    #[command(subcommand)]
    pub action: GroundtruthAction,

    /// Override the views.db path. Defaults to `~/.neoth/views.db`.
    #[arg(long, value_name = "PATH", global = true)]
    pub db: Option<PathBuf>,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum GroundtruthAction {
    /// List active ground-truth rows.
    List {
        /// Filter by scope (default `global`). Pass `*` to list every scope.
        #[arg(long, default_value = "global")]
        scope: String,
        /// Max rows to return.
        #[arg(long, default_value = "50")]
        limit: usize,
    },
    /// Add a new statement.
    Add {
        /// The fact. Stored verbatim (trimmed).
        statement: String,
        /// Scope tag. `global` | `host:<name>` | `session:<id>` | custom.
        #[arg(long, default_value = "global")]
        scope: String,
    },
    /// Revoke an existing row by id. Row stays in the table for audit but
    /// stops appearing in recall.
    Revoke {
        /// Row id (`neoth groundtruth list` shows ids).
        id: i64,
    },
    /// GOLD-ADAPT-MEM-01 — set a fact's trust state. Only `verified` facts are
    /// surfaced into recall; promote a corroborated candidate, or retire one as
    /// `superseded` / `contradicted` / `deprecated`.
    State {
        /// Row id (`neoth groundtruth list` shows ids + current state).
        id: i64,
        /// New state: raw | candidate | verified | superseded | contradicted | deprecated.
        state: String,
    },
    /// GOLD-ADAPT-MEM-02 — list the contradiction ledger (pairs of facts that
    /// disagree). The lower-credibility fact in each pair is auto-flagged
    /// `contradicted` and drops from recall.
    Contradictions {
        /// Run a full contradiction re-scan over all verified facts first.
        #[arg(long)]
        detect: bool,
        /// Include already-dismissed pairs in the listing.
        #[arg(long)]
        resolved: bool,
    },
    /// GOLD-ADAPT-MEM-02 — dismiss a contradiction ledger entry by its id (the
    /// operator judged it a non-conflict). Does NOT change either fact's state.
    ResolveContradiction {
        /// Ledger row id (`neoth groundtruth contradictions` shows ids).
        id: i64,
    },
    /// Run the bilingual Q&A pass — re-entrant version of the wizard step.
    /// Operator can run any time after `neoth init`.
    Ask {
        /// Override the primary language for the prompts (defaults to
        /// freedom.yaml::language_primary, then `en`).
        #[arg(long, value_name = "LANG")]
        lang: Option<String>,
    },
    /// Import claims from a markdown / text file. Each atomic claim
    /// becomes one `idx_groundtruth` row. Phase 28c R-24 GT-6.
    ImportText {
        /// Path to the file. Pass `-` to read from stdin.
        path: String,
        /// Scope tag for every row in this batch.
        #[arg(long, default_value = "global")]
        scope: String,
        /// Skip the heuristic extractor, dump raw lines into the table
        /// (one row per non-empty line). Useful for already-curated lists.
        #[arg(long)]
        raw: bool,
        /// Print extracted claims without inserting. Useful for previewing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Import ground-truth rows from another agent's memory store.
    /// Phase 28c R-24 GT-8.
    ///
    /// Supported sources: hermes (SQLite), openclaw (markdown dir or index.json),
    /// openhuman (SQLite triple store), veronica (JSONL), jsonl (generic
    /// JSONL with the Veronica shape), obsidian (vault dir of manual notes).
    ImportAgent {
        /// Which foreign agent format.
        /// `hermes | openclaw | openclaw-index | openhuman | veronica | jsonl | obsidian`.
        kind: String,
        /// Path to the foreign store. SQLite files for hermes/openhuman,
        /// markdown directory for openclaw, JSONL file for veronica/jsonl.
        path: String,
        /// Print parsed claims without inserting any rows.
        #[arg(long)]
        dry_run: bool,
    },
    /// Scan the local network and persist discovered hosts as ground-truth
    /// rows tagged `host:<name-or-ip>`. Phase 28c R-24 GT-7.
    ///
    /// Default: ARP cache only (zero packets, opt-in). Pass `--nmap <subnet>`
    /// to additionally run `nmap -sn` (generates traffic, requires nmap on
    /// PATH). `--include-mac` is OFF by default — strip MAC addresses
    /// before writing rows. `--aggregate-guests` rolls anonymous hosts
    /// into one per-subnet summary row instead of one row each.
    ImportInfra {
        /// Use the local ARP table (`arp -a` / `ip neigh`).
        #[arg(long)]
        arp: bool,
        /// Run `nmap -sn <subnet>`. Requires nmap on PATH.
        #[arg(long, value_name = "SUBNET")]
        nmap: Option<String>,
        /// Collect MAC addresses. Default OFF per privacy spec.
        #[arg(long)]
        include_mac: bool,
        /// Roll anonymous hosts into a per-subnet summary row.
        #[arg(long)]
        aggregate_guests: bool,
        /// Print discovered hosts without inserting any rows.
        #[arg(long)]
        dry_run: bool,
    },
}

pub async fn run_groundtruth(args: GroundtruthArgs) -> Result<()> {
    let db_path = args.db.clone().unwrap_or_else(store::default_path);
    let conn = store::open(&db_path).context("open views.db")?;

    match args.action {
        GroundtruthAction::List { scope, limit } => list(&conn, &scope, limit, args.output),
        GroundtruthAction::Add { statement, scope } => add(&conn, &statement, &scope, args.output),
        GroundtruthAction::Revoke { id } => revoke(&conn, id, args.output),
        GroundtruthAction::State { id, state } => set_state(&conn, id, &state, args.output),
        GroundtruthAction::Contradictions { detect, resolved } => {
            contradictions(&conn, detect, resolved, args.output).await
        }
        GroundtruthAction::ResolveContradiction { id } => {
            resolve_contradiction(&conn, id, args.output)
        }
        GroundtruthAction::Ask { lang } => {
            drop(conn);
            ask(&db_path, lang.as_deref(), args.output)
        }
        GroundtruthAction::ImportText {
            path,
            scope,
            raw,
            dry_run,
        } => import_text(&conn, &path, &scope, raw, dry_run, args.output),
        GroundtruthAction::ImportAgent {
            kind,
            path,
            dry_run,
        } => import_agent(&conn, &kind, &path, dry_run, args.output),
        GroundtruthAction::ImportInfra {
            arp,
            nmap,
            include_mac,
            aggregate_guests,
            dry_run,
        } => {
            import_infra(
                &conn,
                arp,
                nmap.as_deref(),
                include_mac,
                aggregate_guests,
                dry_run,
                args.output,
            )
            .await
        }
    }
}

fn import_agent(
    conn: &rusqlite::Connection,
    kind: &str,
    path_str: &str,
    dry_run: bool,
    output: OutputFormat,
) -> Result<()> {
    use crate::memory::foreign_import as fi;
    let path = std::path::Path::new(path_str);
    let claims: Vec<fi::ImportedClaim> = match kind {
        "hermes" => fi::read_hermes_db(path)?,
        "openclaw" => {
            // Accept either a single .md file or the layers/ directory.
            if path.is_dir() {
                fi::read_openclaw_dir(path)?
            } else {
                fi::read_openclaw_layer(path)?
            }
        }
        // JV-IMP-01: OpenClaw memory-index JSON (`memories[]` array).
        "openclaw-index" => fi::read_openclaw_memory_index(path)?,
        "openhuman" => fi::read_openhuman_db(path)?,
        "veronica" => {
            fi::read_veronica_jsonl(path, crate::memory::groundtruth::Source::ImportVeronica)?
        }
        "jsonl" => fi::read_veronica_jsonl(
            path,
            // Reuse the Veronica reader for arbitrary JSONL; the row shape
            // is identical. Stamp the source as Veronica so the audit
            // trail says where the format came from.
            crate::memory::groundtruth::Source::ImportVeronica,
        )?,
        // JV-IMP-06: Obsidian vault — walk the dir and import manual notes
        // (i.e. notes WITHOUT `source: openclaw-*` / `source: neoth-*` frontmatter).
        "obsidian" => fi::read_obsidian_manual_notes(path)?,
        other => anyhow::bail!(
            "unknown agent kind '{other}'. \
             Expected: hermes | openclaw | openclaw-index | openhuman | veronica | jsonl | obsidian"
        ),
    };

    if dry_run {
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::json!({
                        "kind": kind,
                        "count": claims.len(),
                        "preview": claims.iter().take(5).map(|c| &c.statement).collect::<Vec<_>>(),
                    })
                );
            }
            OutputFormat::Table => {
                println!(
                    "# {} claim(s) parsed from {kind} (dry-run, no rows inserted)",
                    claims.len()
                );
                for c in claims.iter().take(20) {
                    println!("  · [{}] {}", c.scope, c.statement);
                }
                if claims.len() > 20 {
                    println!("  … and {} more", claims.len() - 20);
                }
            }
        }
        return Ok(());
    }

    let now_ns = crate::time::now_unix_ns_i64();
    let mut inserted = 0usize;
    for c in &claims {
        crate::memory::groundtruth::insert(conn, &c.statement, &c.source, &c.scope, now_ns)?;
        inserted += 1;
    }
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({"inserted": inserted, "kind": kind})
            );
        }
        OutputFormat::Table => {
            println!("imported {inserted} ground-truth row(s) from {kind} at {path_str}");
        }
    }
    Ok(())
}

async fn import_infra(
    conn: &rusqlite::Connection,
    do_arp: bool,
    nmap_subnet: Option<&str>,
    include_mac: bool,
    aggregate_guests: bool,
    dry_run: bool,
    output: OutputFormat,
) -> Result<()> {
    if !do_arp && nmap_subnet.is_none() {
        anyhow::bail!(
            "infra scan requires at least one source. Pass --arp and/or --nmap <subnet>."
        );
    }

    let opts = crate::memory::infra_scan::ScanOptions {
        include_mac,
        aggregate_guests,
    };
    let mut all_hosts = Vec::new();
    if do_arp {
        let hosts = crate::memory::infra_scan::run_arp_scan(opts)
            .await
            .context("ARP scan")?;
        all_hosts.extend(hosts);
    }
    if let Some(subnet) = nmap_subnet {
        let hosts = crate::memory::infra_scan::run_nmap_scan(subnet, opts)
            .await
            .context("nmap scan")?;
        all_hosts.extend(hosts);
    }

    if dry_run {
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::json!({
                        "hosts": all_hosts.iter().map(|h| serde_json::json!({
                            "ip": h.ip,
                            "hostname": h.hostname,
                            "source": h.source.as_str(),
                        })).collect::<Vec<_>>(),
                        "count": all_hosts.len(),
                    })
                );
            }
            OutputFormat::Table => {
                println!("# {} host(s) discovered (dry-run)", all_hosts.len());
                for h in &all_hosts {
                    println!("  · {}", crate::memory::infra_scan::statement_for_host(h));
                }
            }
        }
        return Ok(());
    }

    let now_ns = crate::time::now_unix_ns_i64();
    let mut inserted = 0usize;
    for h in &all_hosts {
        let statement = crate::memory::infra_scan::statement_for_host(h);
        let scope = crate::memory::infra_scan::scope_for_host(h);
        let source = match h.source {
            crate::memory::infra_scan::ScanSource::Arp => {
                crate::memory::groundtruth::Source::ArpScan
            }
            crate::memory::infra_scan::ScanSource::Nmap => {
                crate::memory::groundtruth::Source::NmapScan
            }
        };
        crate::memory::groundtruth::insert(conn, &statement, &source, &scope, now_ns)?;
        inserted += 1;
    }

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "inserted": inserted,
                    "include_mac": include_mac,
                    "aggregate_guests": aggregate_guests,
                })
            );
        }
        OutputFormat::Table => {
            println!("imported {inserted} host row(s) from infra scan");
        }
    }
    Ok(())
}

/// Read `path` (or stdin if `path == "-"`), run the bulk-text extractor,
/// optionally print a preview, optionally insert rows tagged with
/// `Source::BulkText` (or the operator-curated `raw` path).
fn import_text(
    conn: &rusqlite::Connection,
    path: &str,
    scope: &str,
    raw: bool,
    dry_run: bool,
    output: OutputFormat,
) -> Result<()> {
    let body = if path == "-" {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf).context("read stdin")?;
        buf
    } else {
        std::fs::read_to_string(path).with_context(|| format!("read {path}"))?
    };

    let claims: Vec<crate::memory::bulk_text::Claim> = if raw {
        // Operator promises this is already one-claim-per-line. Raw and
        // heuristic paths still share the same cap, canonical normaliser,
        // collision guard, and persistent import ledger.
        crate::memory::bulk_text::extract_claims_raw(&body)
    } else {
        crate::memory::bulk_text::extract_claims_heuristic(&body)
    };

    if dry_run {
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::json!({
                        "claims": claims.iter().map(|c| &c.statement).collect::<Vec<_>>(),
                        "count": claims.len(),
                    })
                );
            }
            OutputFormat::Table => {
                println!(
                    "# {} claim(s) extracted (dry-run, no rows inserted)",
                    claims.len()
                );
                for c in &claims {
                    println!("  · {}", c.statement);
                }
            }
        }
        return Ok(());
    }

    let now_ns = crate::time::now_unix_ns_i64();
    let mut inserted = 0usize;
    let mut skipped = 0usize;
    let mut tombstoned = 0usize;
    for c in &claims {
        match crate::memory::bulk_text::persist_claim(conn, c, scope, now_ns)? {
            crate::memory::bulk_text::PersistClaimOutcome::Inserted { .. } => inserted += 1,
            crate::memory::bulk_text::PersistClaimOutcome::SkippedActive { .. } => skipped += 1,
            crate::memory::bulk_text::PersistClaimOutcome::SkippedTombstone { .. } => {
                skipped += 1;
                tombstoned += 1;
            }
        }
    }

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "inserted": inserted,
                    "skipped": skipped,
                    "tombstoned": tombstoned,
                    "scope": scope,
                    "source": "bulk-text",
                })
            );
        }
        OutputFormat::Table => {
            println!(
                "imported {inserted} ground-truth row(s) from {path}; \
                 skipped {skipped} known claim(s), including {tombstoned} tombstone(s) \
                 (scope={scope})"
            );
        }
    }
    Ok(())
}

/// Run the Q&A pass against the bundled (or operator-edited) question bank.
/// Re-entrant: every invocation appends new ground-truth rows. To replace
/// rather than append, the operator can `revoke` first.
fn ask(db_path: &std::path::Path, lang: Option<&str>, output: OutputFormat) -> Result<()> {
    let bank = crate::cli::groundtruth_wizard::load_bank()?;
    let lang_owned: String = if let Some(l) = lang {
        l.to_string()
    } else {
        crate::config::FreedomConfig::load_from_default_path_or_default()?
            .language_primary
            .unwrap_or_else(|| "en".to_string())
    };
    let answers = crate::cli::groundtruth_wizard::run_qa(&bank, &lang_owned)?;
    let now_ns = crate::time::now_unix_ns_i64();
    let n = crate::cli::groundtruth_wizard::persist_answers(
        db_path,
        &bank,
        &answers,
        &lang_owned,
        now_ns,
    )?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({"inserted": n, "answered": answers.iter().filter(|a| a.value.is_some()).count()})
            );
        }
        OutputFormat::Table => {
            println!("{n} ground-truth row(s) stored from Q&A pass.");
        }
    }
    Ok(())
}

fn list(
    conn: &rusqlite::Connection,
    scope: &str,
    limit: usize,
    output: OutputFormat,
) -> Result<()> {
    // Operator inspection: show ALL trust states (incl. candidates) so the
    // `fact_state` column is meaningful — only the recall surface gates on
    // verified (GOLD-ADAPT-MEM-01).
    let rows = if scope == "*" {
        groundtruth::surface_for_recall(conn, limit, true)?
    } else {
        groundtruth::list_for_scope(conn, scope)?
            .into_iter()
            .take(limit)
            .collect()
    };

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        OutputFormat::Table => {
            if rows.is_empty() {
                println!("no active ground-truth rows for scope `{scope}`");
                return Ok(());
            }
            println!(
                "# {} active ground-truth row(s) (scope={scope})",
                rows.len()
            );
            for g in &rows {
                println!(
                    "  [{:>4}] {:<11} {:<22} {:<24}  {}",
                    g.id, g.fact_state, g.source, g.scope, g.statement,
                );
                // GOLD-ADAPT-NN-MEM-03: show evidence provenance when present.
                let ev_ids: Vec<i64> = serde_json::from_str(&g.evidence)
                    .with_context(|| format!("parse evidence for ground-truth row {}", g.id))?;
                if !ev_ids.is_empty() {
                    println!(
                        "         maturity={} conf={:.2} confirmed={} evidence={:?}",
                        g.maturity,
                        g.confidence,
                        g.confirmed_count,
                        &ev_ids[..ev_ids.len().min(5)],
                    );
                }
            }
        }
    }
    Ok(())
}

fn add(
    conn: &rusqlite::Connection,
    statement: &str,
    scope: &str,
    output: OutputFormat,
) -> Result<()> {
    let now_ns = crate::time::now_unix_ns_i64();
    let id = groundtruth::insert(
        conn,
        statement,
        &groundtruth::Source::OperatorRuntime,
        scope,
        now_ns,
    )?;
    info!(id, scope, "ground-truth row inserted");

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({"id": id, "scope": scope, "statement": statement})
            );
        }
        OutputFormat::Table => {
            println!("added ground-truth #{id} (scope={scope})");
        }
    }
    Ok(())
}

fn revoke(conn: &rusqlite::Connection, id: i64, output: OutputFormat) -> Result<()> {
    let now_ns = crate::time::now_unix_ns_i64();
    let modified = groundtruth::revoke(conn, id, now_ns)?;
    match (modified, output) {
        (true, OutputFormat::Json | OutputFormat::Jsonl) => {
            println!("{}", serde_json::json!({"revoked": id}));
        }
        (true, OutputFormat::Table) => println!("revoked ground-truth #{id}"),
        (false, _) => {
            anyhow::bail!("no ground-truth row with id {id}");
        }
    }
    Ok(())
}

/// GOLD-ADAPT-MEM-01 — `neoth groundtruth state <id> <state>`: operator-driven
/// trust-state transition (promote a corroborated candidate, supersede,
/// contradict, or deprecate a fact).
fn set_state(
    conn: &rusqlite::Connection,
    id: i64,
    state: &str,
    output: OutputFormat,
) -> Result<()> {
    let Some(fs) = groundtruth::FactState::parse(state) else {
        anyhow::bail!(
            "unknown fact state '{state}' — use one of: \
             raw, candidate, verified, superseded, contradicted, deprecated"
        );
    };
    let changed = groundtruth::set_fact_state(conn, id, fs)?;
    if !changed {
        anyhow::bail!("no ground-truth row with id {id}");
    }
    info!(id, state = fs.as_str(), "ground-truth fact state set");
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::json!({"id": id, "state": fs.as_str()}));
        }
        OutputFormat::Table => println!("ground-truth #{id} → {}", fs.as_str()),
    }
    Ok(())
}

/// GOLD-ADAPT-MEM-02 — `neoth groundtruth contradictions [--detect] [--resolved]`.
async fn contradictions(
    conn: &rusqlite::Connection,
    detect: bool,
    resolved: bool,
    output: OutputFormat,
) -> Result<()> {
    let now_ns = crate::time::now_unix_ns_i64();
    let detected = if detect {
        // Use semantic (embedding cosine) subject-similarity when an embed
        // provider is configured + loadable; the scan falls back to deterministic
        // Jaccard per-pair otherwise (same seam as cli/dream.rs).
        let config = crate::config::FreedomConfig::load_from_default_path()
            .context("load freedom.yaml for contradiction scan")?;
        let embed = crate::providers::embed_provider_from_config(&config).await;
        info!(semantic = embed.is_some(), "contradiction scan starting");
        crate::memory::contradiction::scan_contradictions(conn, now_ns, embed.as_deref()).await?
    } else {
        0
    };
    let rows = crate::memory::contradiction::list_contradictions(conn, resolved)?;
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({ "detected_new": detected, "ledger": rows })
            );
        }
        OutputFormat::Table => {
            if detect {
                println!("contradiction scan: {detected} new pair(s) detected");
            }
            if rows.is_empty() {
                println!("no contradictions in the ledger");
                return Ok(());
            }
            println!(
                "# {} contradiction(s){}",
                rows.len(),
                if resolved { " (incl. dismissed)" } else { "" }
            );
            for c in &rows {
                let mark = if c.decision == "dismissed" {
                    " [dismissed]"
                } else {
                    ""
                };
                println!(
                    "  [{:>4}] fact {} vs {}  conf={:.2}{}",
                    c.ledger_id, c.fact_a_id, c.fact_b_id, c.confidence, mark,
                );
            }
        }
    }
    Ok(())
}

/// GOLD-ADAPT-MEM-02 — `neoth groundtruth resolve-contradiction <id>`: dismiss a
/// ledger entry (operator judged it a non-conflict).
fn resolve_contradiction(conn: &rusqlite::Connection, id: i64, output: OutputFormat) -> Result<()> {
    let now_ns = crate::time::now_unix_ns_i64();
    let ok = crate::memory::contradiction::resolve(conn, id, now_ns)?;
    if !ok {
        anyhow::bail!("no pending contradiction ledger row #{id}");
    }
    info!(id, "contradiction ledger entry dismissed");
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::json!({"resolved": id}));
        }
        OutputFormat::Table => println!("dismissed contradiction #{id}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_text_dry_run_is_read_only_for_facts_and_fingerprints() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("claims.txt");
        std::fs::write(
            &input,
            "The operator builds NEOTH on Windows.\nThe gateway stays on the private network.\n",
        )
        .unwrap();
        let conn = crate::memory::store::open(&dir.path().join("views.db")).unwrap();
        import_text(
            &conn,
            input.to_str().unwrap(),
            "global",
            false,
            true,
            OutputFormat::Table,
        )
        .unwrap();

        let facts: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_groundtruth", [], |row| row.get(0))
            .unwrap();
        let fingerprints: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ground_truth_fingerprints",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((facts, fingerprints), (0, 0));
    }
}
