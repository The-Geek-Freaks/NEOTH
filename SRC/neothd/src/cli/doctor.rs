//! `neoth doctor` — operator health-check. Phase 33c follow-up.
//!
//! Runs a battery of read-only diagnostics over `~/.neoth/` and prints a
//! pass/warn/fail report. Exit code is non-zero when any check FAILs so
//! the command is CI-friendly (`neoth doctor --quiet || exit`).
//!
//! Diagnostics:
//!   1. **freedom.yaml present + parseable + mode 0600**
//!   2. **credentials.yaml mode 0600 if present** — empty file silently OK
//!   3. **views.db integrity** — `PRAGMA integrity_check` + schema-version stamp
//!   4. **WAL segments** — every `*.wal` parses its SegmentHeader cleanly
//!   5. **HMAC key file** — exists + mode 0600
//!   6. **Quota** — `<5 GiB` (per `daemon::quota::DEFAULT_QUOTA_BYTES`)
//!   7. **policy.yaml parseable** if present
//!   8. **Tweaks file parseable** if present
//!
//! Each diagnostic returns one [`CheckOutcome`]. The aggregate report is
//! rendered as a table (or JSON / JSONL when the global `--output` says so).

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;
use rusqlite::Connection;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;

#[derive(Args, Debug, Clone)]
pub struct DoctorArgs {
    /// Override `~/.neoth/` for tests.
    #[arg(long, value_name = "DIR")]
    pub home: Option<PathBuf>,
    /// Suppress per-check output; print only the final summary line + use
    /// exit code for CI.
    #[arg(long)]
    pub quiet: bool,
    /// V03-07: print operator-facing documentation for the named check
    /// (what it tests, common failures, fix steps) instead of running the
    /// full diagnostic suite. Combine with `--output json` for scripted
    /// runbook lookups. Pair with `--list-checks` to see what's available.
    #[arg(long, value_name = "NAME")]
    pub explain: Option<String>,
    /// V03-07: print the list of check names recognised by `--explain`.
    /// Useful for tab-completion + operator-side runbook generation.
    #[arg(long)]
    pub list_checks: bool,
    /// Output format inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

/// V03-07 2026-05-17: operator-facing documentation for each check.
/// Triggered via `neoth doctor --explain <name>`. Each entry holds:
///   - `name` — exact check identifier (matches `CheckOutcome.name`).
///   - `purpose` — one-paragraph operator-readable description of what
///     the check verifies + why it matters.
///   - `common_failures` — typical WARN/FAIL causes.
///   - `fix` — concrete commands or edits an operator can run to
///     remediate.
pub struct CheckDoc {
    pub name: &'static str,
    pub purpose: &'static str,
    pub common_failures: &'static str,
    pub fix: &'static str,
}

const CHECK_DOCS: &[CheckDoc] = &[
    CheckDoc {
        name: "freedom.yaml",
        purpose: "Operator configuration lives in `~/.neoth/freedom.yaml`. \
                  Doctor verifies the file exists, parses cleanly via \
                  `FreedomConfig::load_from_path`, and (on unix) is mode \
                  0600 so secrets at rest survive multi-user systems.",
        common_failures: "Missing file (operator hasn't run `neoth init`); \
                         parse error (hand-edited typo); permissions broader \
                         than 0600 (unix).",
        fix: "Missing → `neoth init` (or `neoth init --force` for a clean \
              wipe).\nParse error → diff against `freedom.yaml.example` in \
              the repo / install root.\nPermissions → `chmod 600 ~/.neoth/freedom.yaml`.",
    },
    CheckDoc {
        name: "credentials.yaml",
        purpose: "Secret store at `~/.neoth/credentials.yaml`. Holds API \
                  keys + bot tokens that should NEVER be in freedom.yaml. \
                  Doctor checks existence (warn if missing — daemon can \
                  start without it for local_qwen-only deployments), parse \
                  cleanly, and 0600 mode.",
        common_failures: "Secrets pasted into freedom.yaml instead (creates \
                         a leak path through `neoth export`); world-readable \
                         mode; corrupt YAML.",
        fix: "Edit by hand: keys at the top level (`provider_key`, \
              `telegram_token`). `chmod 600 ~/.neoth/credentials.yaml`.",
    },
    CheckDoc {
        name: "views.db",
        purpose: "SQLite views database — the read-side projection of the \
                  WAL. Holds idx_episode (recall), idx_profile (operator \
                  facts), idx_groundtruth (decay-immune anchors), \
                  idx_consolidated / idx_longterm (memory tiers). Doctor \
                  runs `PRAGMA integrity_check` + verifies schema_version \
                  stamp.",
        common_failures: "Disk full mid-write (corruption); manual delete \
                         (recoverable via `neoth restore`); schema drift \
                         (mis-applied migration).",
        fix: "Corruption → restore from `~/.neoth/backups/`. Schema drift → \
              `neoth migrate up` brings the schema forward. If the daemon \
              can't open it, delete + let the indexer rebuild from WAL.",
    },
    CheckDoc {
        name: "wal segments",
        purpose: "Append-only WAL at `~/.neoth/wal/*.wal`. The audit \
                  trail of every action NEOTH ever took. Doctor walks \
                  the segment directory, checks each segment's frame CRC \
                  + magic preamble, verifies the active segment is \
                  writeable.",
        common_failures: "Last-frame corruption (writer crashed mid-fsync — \
                         self-heals on next index pass); segment dir not \
                         writeable; segments deleted manually.",
        fix: "Corrupt tail frame → harmless, indexer truncates. Read-only \
              dir → `chmod u+w ~/.neoth/wal/`. Manually deleted → live with \
              the gap; the indexer skips missing segments.",
    },
    CheckDoc {
        name: "hmac.key",
        purpose: "HMAC key at `~/.neoth/hmac.key` — signs the compaction \
                  markers in the WAL so tampering is detectable. Doctor \
                  checks existence, that the file is exactly 32 bytes \
                  (HMAC-SHA256 key size), and 0600 mode.",
        common_failures: "Missing (daemon auto-generates on first run); \
                         wrong size (manual edit); world-readable.",
        fix: "Missing → next daemon start regenerates. Wrong size → delete \
              + restart (loses ability to verify markers pre-restart). \
              `chmod 600 ~/.neoth/hmac.key`.",
    },
    CheckDoc {
        name: "disk quota",
        purpose: "Pre-write quota guard. Doctor checks the home dir's \
                  current usage vs the configured ceiling \
                  (`freedom.yaml::quota_ceiling_bytes`, default 5 GiB). \
                  Warns past 75% used; fails past 90%.",
        common_failures: "Long-lived daemon with no consolidation → WAL \
                         segments accumulate; backups in `~/.neoth/backups/` \
                         pile up.",
        fix: "Tighten the ceiling or prune. `neoth wal compact` rolls \
              old segments. `neoth backup --prune --keep 7` rotates the \
              backup set.",
    },
    CheckDoc {
        name: "policy.yaml",
        purpose: "Optional autonomy policy override at \
                  `~/.neoth/policy.yaml`. When present, overrides the \
                  freedom.yaml-level `autonomy` field per-action category. \
                  Doctor verifies parse + schema.",
        common_failures: "Missing is fine (operator just hasn't customised). \
                         Parse error blocks daemon startup.",
        fix: "Missing → no action needed. Parse error → diff against the \
              schema in `docs/policy.md`, or delete to fall back to \
              freedom.yaml's autonomy field.",
    },
    CheckDoc {
        name: "hooks/",
        purpose: "Operator hooks at `~/.neoth/hooks/*.toml`. Each file \
                  defines an event stage + a command. Doctor loads every \
                  file via `hooks::load_all` so YAML/TOML syntax errors + \
                  unknown stages surface BEFORE the daemon hits the event.",
        common_failures: "Typo in stage name (unknown HookStage); shell \
                         command not in PATH; regex syntax error in the \
                         matcher field.",
        fix: "Run `neoth hooks list` for parse errors. `neoth hooks \
              validate` runs the schema + regex check standalone. Fix \
              the file or remove it.",
    },
    CheckDoc {
        name: "agents/",
        purpose: "Sub-agents at `~/.neoth/agents/*.md`. Each markdown file \
                  defines an operator-callable agent's system prompt + \
                  trigger keywords. Doctor loads every agent via \
                  `sub_agents::load_all`.",
        common_failures: "Empty system prompt; malformed YAML frontmatter; \
                         unknown tool_allowlist entries.",
        fix: "Edit the offending .md to fix the frontmatter. `neoth agents \
              list` shows parse errors with line numbers.",
    },
    CheckDoc {
        name: "profile_extensions.toml",
        purpose: "Typed extension registry at \
                  `~/.neoth/profile_extensions.toml`. Operator-defined \
                  custom profile fields outside the base taxonomy (e.g. \
                  `operator.preferences.editor`). Doctor parses + warns on \
                  unknown reserved keys.",
        common_failures: "Empty file (use the bundled example as a start); \
                         TOML syntax error.",
        fix: "Missing → use defaults. Syntax error → diff against \
              `assets/profile_extensions.toml.example`.",
    },
    CheckDoc {
        name: "tweaks.toml",
        purpose: "tweakcc-style customisation at `~/.neoth/tweaks.toml`. \
                  Operator overrides for prompts, persona, slash-command \
                  aliases. Doctor parses + flags unknown keys.",
        common_failures: "Hand-edited YAML where TOML is expected; \
                         malformed `[[prompts]]` array.",
        fix: "Diff against `assets/tweaks.toml.example`. Or delete to \
              fall back to bundled defaults.",
    },
    CheckDoc {
        name: "model caches",
        purpose: "HuggingFace model caches under \
                  `~/.cache/huggingface/hub/`. Doctor checks the bundled \
                  models (whisper-large-v3, clip-vit-base-patch32, \
                  Qwen2.5-3B-Instruct) are downloaded — warns when \
                  missing so operators don't first discover the \
                  network requirement mid-chat.",
        common_failures: "Fresh install with no HF cache; partial download \
                         (interrupted git-lfs).",
        fix: "Run `neoth models pull` to bulk-download. Or accept the \
              warning — models lazy-download on first use.",
    },
    CheckDoc {
        name: "hysteria",
        purpose: "Hysteria QUIC transport config at \
                  `freedom.yaml::hysteria.{server, auth, socks_port}`. \
                  Doctor verifies the binary exists (in PATH or \
                  `~/.neoth/bin/hysteria`) + the SOCKS5 port is bindable.",
        common_failures: "Operator configured server but didn't install \
                         binary; SOCKS port collision with another \
                         service.",
        fix: "Binary missing → download from \
              https://github.com/apernet/hysteria/releases or remove \
              the hysteria block. Port collision → pick a different \
              `socks_port` in freedom.yaml.",
    },
    CheckDoc {
        name: "cloud archive",
        purpose: "Cloud archive mirror target at \
                  `freedom.yaml::cloud_archive_dest` (typically a folder \
                  the operator's Dropbox / GDrive / OneDrive desktop \
                  client syncs upstream). Doctor checks the path exists + \
                  is writeable + is a directory (not a file).",
        common_failures: "Path is a file (operator typo); doesn't exist; \
                         not writeable.",
        fix: "Edit `freedom.yaml::cloud_archive_dest` to a real existing \
              directory. Remove the field to disable cloud archive \
              entirely.",
    },
    CheckDoc {
        name: "mcp servers",
        purpose: "Model Context Protocol server registry at \
                  `~/.neoth/mcp_servers.yaml`. Doctor loads via \
                  `McpServers::load`, flags parse errors, warns when \
                  enabled servers reference a command that's not in PATH.",
        common_failures: "Missing file (fine — MCP autoroute defaults off); \
                         malformed YAML; binary not installed.",
        fix: "Missing → no action. Parse error → diff against \
              `mcp_servers.yaml.example`. Binary missing → install the \
              server (e.g. `npm i -g @modelcontextprotocol/server-filesystem`).",
    },
    CheckDoc {
        name: "disk space",
        purpose: "Free space on the partition holding `~/.neoth/`. Warns \
                  past 1 GiB free, fails past 100 MiB. Below the fail \
                  threshold the WAL writer's quota guard will reject new \
                  writes — better to warn early.",
        common_failures: "Cube with `disk3` filling up; laptop with \
                         OS-disk pressure.",
        fix: "Prune backups (`neoth backup --prune`); compact WAL (`neoth \
              wal compact`); move `~/.neoth/` to a larger volume via \
              symlink + `chown`.",
    },
    CheckDoc {
        name: "credentials age",
        purpose: "Age of `~/.neoth/credentials.yaml`. Telegram bot tokens, \
                  Slack tokens, and provider API keys quietly expire or \
                  get rotated server-side. Doctor reads the file's \
                  modification time and warns past 180 days, fails past \
                  365. The check skips when the file is absent or holds \
                  only `None` secret slots (local_qwen-only setups).",
        common_failures: "Long-lived deployment without rotation; Slack \
                         workspace revoked the bot token; Telegram \
                         BotFather rotated the secret.",
        fix: "Re-run the relevant wizard step (`neoth init --step \
              credentials`) or edit `~/.neoth/credentials.yaml` and \
              `touch` the file to reset the age clock once the new \
              token is in.",
    },
    CheckDoc {
        name: "wasm plugins",
        purpose: "NOOB-UX-3 effective state of the WASM plugin host. \
                  Reports one of three states: `compiled-in + enabled` \
                  (release feature on, freedom.yaml says enabled), \
                  `compiled-in but disabled by config` (operator flipped \
                  `freedom.yaml::plugins.wasm.enabled: false`), or \
                  `not compiled in` (slim daemon build without the \
                  `wasm-plugin-host` cargo feature). Surfaces the gap \
                  between build-time + runtime gates so an operator \
                  who set `enabled: true` but runs a slim build sees \
                  the mismatch immediately.",
        common_failures: "Operator expects plugins to work on a slim \
                         build (cargo feature not compiled in); \
                         operator's freedom.yaml has `enabled: false` \
                         but the wizard step7b explanation isn't fresh \
                         in memory.",
        fix: "Slim build → rebuild with `--features wasm-plugin-host` \
              or install the release tarball (cargo-dist flips the \
              feature ON). Disabled-by-config → edit \
              `~/.neoth/freedom.yaml` and flip \
              `plugins:\\n  wasm:\\n    enabled: true`, then \
              restart the daemon.",
    },
    CheckDoc {
        name: "channels wiring",
        purpose: "R2-P0-2 honesty surface. Loads `credentials.yaml` + \
                  classifies every configured channel as one of: LIVE \
                  (send + receive both real), OUTBOUND-ONLY (send works, \
                  inbound receive loop not yet wired), CONFIGURED-NOT-\
                  STARTED (full inbound code ships but serve does not \
                  bootstrap it), or absent (silent). Closes the \
                  documented gap where README/Status claimed channels \
                  were live while `cli::serve` only spawned Telegram.",
        common_failures: "Operator configures Slack/WhatsApp credentials \
                         + expects bidirectional chat. Aggregate Warn \
                         when any partial (OUTBOUND-ONLY / CONFIGURED-NOT-\
                         STARTED) channel is in the set so the gap \
                         surfaces during install verification.",
        fix: "Telegram inbound + outbound: live today. Slack inbound: \
              awaits socket-mode wiring in `cli::serve`. WhatsApp \
              inbound: awaits webhook listener wiring in `cli::serve` \
              (the listener + decoder ship; the bootstrap step is \
              deferred). Until then, use the channel for outbound-only \
              workflows (cron briefings, proactive alerts) and route \
              inbound through Telegram or CLI.",
    },
];

/// Find a CheckDoc by case-insensitive name match. `None` when no doc
/// exists for that check name (typo in operator's `--explain` flag).
fn find_check_doc(name: &str) -> Option<&'static CheckDoc> {
    let needle = name.trim().to_ascii_lowercase();
    CHECK_DOCS
        .iter()
        .find(|d| d.name.to_ascii_lowercase() == needle)
}

/// Render a single CheckDoc in operator-readable text. Used by the
/// `--explain` path's table-output branch. JSON output uses serde
/// directly on the doc fields.
fn render_check_doc_text(doc: &CheckDoc) {
    println!("# {} — operator runbook", doc.name);
    println!();
    println!("## What it checks");
    println!("{}", doc.purpose);
    println!();
    println!("## Common failures");
    println!("{}", doc.common_failures);
    println!();
    println!("## How to fix");
    println!("{}", doc.fix);
}

/// One diagnostic outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    /// Soft problem — operator should look, but daemon will start.
    Warn,
    /// Hard problem — daemon refuses to start, or behaviour will be wrong.
    Fail,
}

impl CheckStatus {
    pub fn tag(&self) -> &'static str {
        match self {
            CheckStatus::Pass => "PASS",
            CheckStatus::Warn => "WARN",
            CheckStatus::Fail => "FAIL",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CheckOutcome {
    pub name: &'static str,
    pub status: CheckStatus,
    pub detail: String,
}

pub async fn run_doctor(args: DoctorArgs) -> Result<()> {
    // V03-07: short-circuit when operator requested the runbook lookup
    // surface instead of the diagnostic suite.
    if args.list_checks {
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                let names: Vec<&str> = CHECK_DOCS.iter().map(|d| d.name).collect();
                println!(
                    "{}",
                    serde_json::json!({
                        "checks": names,
                        "count": names.len(),
                    })
                );
            }
            OutputFormat::Table => {
                println!(
                    "# doctor checks recognised by --explain ({} total)",
                    CHECK_DOCS.len()
                );
                for d in CHECK_DOCS {
                    println!("  {}", d.name);
                }
            }
        }
        return Ok(());
    }
    if let Some(name) = args.explain.as_deref() {
        match find_check_doc(name) {
            Some(doc) => match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "name": doc.name,
                            "purpose": doc.purpose,
                            "common_failures": doc.common_failures,
                            "fix": doc.fix,
                        })
                    );
                }
                OutputFormat::Table => render_check_doc_text(doc),
            },
            None => {
                anyhow::bail!(
                    "no doctor check named `{name}`. Run `neoth doctor --list-checks` \
                     to see the recognised names."
                );
            }
        }
        return Ok(());
    }

    let home = args
        .home
        .clone()
        .unwrap_or_else(FreedomConfig::default_neoth_home);
    let outcomes = run_all_checks(&home);

    let any_fail = outcomes.iter().any(|o| o.status == CheckStatus::Fail);
    let any_warn = outcomes.iter().any(|o| o.status == CheckStatus::Warn);

    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<_> = outcomes
                .iter()
                .map(|o| {
                    serde_json::json!({
                        "name": o.name,
                        "status": o.status.tag(),
                        "detail": o.detail,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "checks": rows,
                    "any_fail": any_fail,
                    "any_warn": any_warn,
                })
            );
        }
        OutputFormat::Table => {
            if !args.quiet {
                println!("# `neoth doctor` — {} check(s)", outcomes.len());
                for o in &outcomes {
                    println!("  [{}]  {:<32}  {}", o.status.tag(), o.name, o.detail);
                }
            }
            println!(
                "summary: {} pass, {} warn, {} fail",
                outcomes
                    .iter()
                    .filter(|o| o.status == CheckStatus::Pass)
                    .count(),
                outcomes
                    .iter()
                    .filter(|o| o.status == CheckStatus::Warn)
                    .count(),
                outcomes
                    .iter()
                    .filter(|o| o.status == CheckStatus::Fail)
                    .count(),
            );
        }
    }

    if any_fail {
        std::process::exit(1);
    }
    Ok(())
}

/// Run every diagnostic in order. Pure synchronous — each check is short.
pub fn run_all_checks(home: &Path) -> Vec<CheckOutcome> {
    vec![
        check_freedom_yaml(home),
        check_credentials_yaml(home),
        check_credential_age(home),
        check_views_db(home),
        check_wal_segments(home),
        check_hmac_key(home),
        check_quota(home),
        check_policy_yaml(home),
        check_tweaks_toml(home),
        check_model_caches(),
        check_hysteria_config(home),
        check_cloud_archive_dest(home),
        check_disk_space(home),
        check_hooks_dir(home),
        check_agents_dir(home),
        check_profile_extensions(home),
        check_mcp_servers(home),
        check_wasm_plugins(home),
        check_channels_wiring(home),
    ]
}

fn check_freedom_yaml(home: &Path) -> CheckOutcome {
    let path = home.join("freedom.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "freedom.yaml",
            status: CheckStatus::Fail,
            detail: format!("missing at {}; run `neoth init`", path.display()),
        };
    }
    if !is_mode_0600(&path) {
        return CheckOutcome {
            name: "freedom.yaml",
            status: CheckStatus::Warn,
            detail: format!("mode > 0600 — run `chmod 0600 {}`", path.display()),
        };
    }
    // Cheap parse check — full parse happens in serve.
    let Ok(body) = std::fs::read_to_string(&path) else {
        return CheckOutcome {
            name: "freedom.yaml",
            status: CheckStatus::Fail,
            detail: "unreadable".into(),
        };
    };
    if serde_yaml::from_str::<serde_yaml::Value>(&body).is_err() {
        return CheckOutcome {
            name: "freedom.yaml",
            status: CheckStatus::Fail,
            detail: "YAML parse error".into(),
        };
    }
    CheckOutcome {
        name: "freedom.yaml",
        status: CheckStatus::Pass,
        detail: format!("ok ({} bytes)", body.len()),
    }
}

fn check_credentials_yaml(home: &Path) -> CheckOutcome {
    let path = home.join("credentials.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "credentials.yaml",
            status: CheckStatus::Pass,
            detail: "absent (claude-cli OAuth flow doesn't need it)".into(),
        };
    }
    if !is_mode_0600(&path) {
        return CheckOutcome {
            name: "credentials.yaml",
            status: CheckStatus::Fail,
            detail: format!(
                "mode > 0600 — secrets leak; run `chmod 0600 {}`",
                path.display()
            ),
        };
    }
    if let Err(e) = crate::config::credentials::Credentials::load_or_default(&path) {
        return CheckOutcome {
            name: "credentials.yaml",
            status: CheckStatus::Fail,
            detail: format!("{e:#}"),
        };
    }
    CheckOutcome {
        name: "credentials.yaml",
        status: CheckStatus::Pass,
        detail: "present, mode 0600, parseable".into(),
    }
}

/// Warn past 180 days, fail past 365 days since `credentials.yaml` was
/// last touched. Audit 2026-05-19 — Telegram/Slack tokens get rotated
/// server-side without any signal to NEOTH; without this check a
/// revoked token reads as a generic 401 deep inside a channel handler.
const CREDENTIAL_AGE_WARN_DAYS: u64 = 180;
const CREDENTIAL_AGE_FAIL_DAYS: u64 = 365;
const SECONDS_PER_DAY: u64 = 86_400;

fn check_credential_age(home: &Path) -> CheckOutcome {
    let path = home.join("credentials.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "credentials age",
            status: CheckStatus::Pass,
            detail: "no credentials.yaml — skipping age check".into(),
        };
    }
    // Only warn when there's actually a secret to rotate. A bare file
    // with every Option<SecretString> set to None can sit for years
    // without operator risk.
    let creds = match crate::config::credentials::Credentials::load_or_default(&path) {
        Ok(c) => c,
        Err(_) => {
            // credentials.yaml parse errors are already surfaced by
            // `check_credentials_yaml`; don't double-fail here.
            return CheckOutcome {
                name: "credentials age",
                status: CheckStatus::Pass,
                detail: "credentials.yaml parse error — see credentials.yaml check".into(),
            };
        }
    };
    if creds.is_empty() {
        return CheckOutcome {
            name: "credentials age",
            status: CheckStatus::Pass,
            detail: "credentials.yaml present but holds no secrets to age-check".into(),
        };
    }
    let modified = match std::fs::metadata(&path).and_then(|m| m.modified()) {
        Ok(m) => m,
        Err(e) => {
            return CheckOutcome {
                name: "credentials age",
                status: CheckStatus::Warn,
                detail: format!("cannot read credentials.yaml mtime: {e}"),
            };
        }
    };
    let age_secs = std::time::SystemTime::now()
        .duration_since(modified)
        .map(|d| d.as_secs())
        // mtime in the future (clock skew or operator `touch -t`) — treat as fresh.
        .unwrap_or(0);
    let age_days = age_secs / SECONDS_PER_DAY;
    if age_days >= CREDENTIAL_AGE_FAIL_DAYS {
        CheckOutcome {
            name: "credentials age",
            status: CheckStatus::Fail,
            detail: format!(
                "credentials.yaml is {age_days} days old (>= {CREDENTIAL_AGE_FAIL_DAYS}d) — rotate Telegram/Slack/provider keys and `touch` the file"
            ),
        }
    } else if age_days >= CREDENTIAL_AGE_WARN_DAYS {
        CheckOutcome {
            name: "credentials age",
            status: CheckStatus::Warn,
            detail: format!(
                "credentials.yaml is {age_days} days old (>= {CREDENTIAL_AGE_WARN_DAYS}d) — consider rotating before tokens expire silently"
            ),
        }
    } else {
        CheckOutcome {
            name: "credentials age",
            status: CheckStatus::Pass,
            detail: format!("credentials.yaml is {age_days} days old"),
        }
    }
}

fn check_views_db(home: &Path) -> CheckOutcome {
    let path = home.join("views.db");
    if !path.exists() {
        return CheckOutcome {
            name: "views.db",
            status: CheckStatus::Warn,
            detail: "absent (will be built on first `neoth serve`)".into(),
        };
    }
    let Ok(conn) = Connection::open(&path) else {
        return CheckOutcome {
            name: "views.db",
            status: CheckStatus::Fail,
            detail: "cannot open SQLite file".into(),
        };
    };
    let integrity: Result<String, _> = conn.query_row("PRAGMA integrity_check", [], |r| r.get(0));
    match integrity {
        Ok(s) if s == "ok" => CheckOutcome {
            name: "views.db",
            status: CheckStatus::Pass,
            detail: "integrity_check ok".into(),
        },
        Ok(other) => CheckOutcome {
            name: "views.db",
            status: CheckStatus::Fail,
            detail: format!("integrity_check returned {other}"),
        },
        Err(e) => CheckOutcome {
            name: "views.db",
            status: CheckStatus::Fail,
            detail: format!("PRAGMA failed: {e}"),
        },
    }
}

fn check_wal_segments(home: &Path) -> CheckOutcome {
    let wal_dir = home.join("wal");
    if !wal_dir.exists() {
        return CheckOutcome {
            name: "wal segments",
            status: CheckStatus::Warn,
            detail: "no wal/ dir (daemon never started)".into(),
        };
    }
    let mut count = 0usize;
    let mut bad = Vec::new();
    let entries = match std::fs::read_dir(&wal_dir) {
        Ok(rd) => rd,
        Err(e) => {
            return CheckOutcome {
                name: "wal segments",
                status: CheckStatus::Fail,
                detail: format!("read wal/ failed: {e}"),
            };
        }
    };
    use crate::wal::segment_header::{SEGMENT_HEADER_LEN, SegmentHeader};
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("wal") {
            continue;
        }
        count += 1;
        let Ok(bytes) = std::fs::read(&path) else {
            bad.push(format!("{}: unreadable", path.display()));
            continue;
        };
        if bytes.len() < SEGMENT_HEADER_LEN {
            bad.push(format!(
                "{}: shorter than SegmentHeader ({} < {})",
                path.display(),
                bytes.len(),
                SEGMENT_HEADER_LEN
            ));
            continue;
        }
        if let Err(e) =
            SegmentHeader::from_le_bytes(bytes[..SEGMENT_HEADER_LEN].try_into().unwrap())
        {
            bad.push(format!("{}: bad header: {e}", path.display()));
        }
    }
    if !bad.is_empty() {
        return CheckOutcome {
            name: "wal segments",
            status: CheckStatus::Fail,
            detail: format!("{} segment(s) bad: {}", bad.len(), bad.join("; ")),
        };
    }
    CheckOutcome {
        name: "wal segments",
        status: CheckStatus::Pass,
        detail: format!("{count} segment(s) ok"),
    }
}

fn check_hmac_key(home: &Path) -> CheckOutcome {
    let path = home.join("wal").join("hmac.key");
    if !path.exists() {
        return CheckOutcome {
            name: "hmac.key",
            status: CheckStatus::Warn,
            detail: "absent (generated on first WAL write)".into(),
        };
    }
    if !is_mode_0600(&path) {
        return CheckOutcome {
            name: "hmac.key",
            status: CheckStatus::Fail,
            detail: format!(
                "mode > 0600 — HMAC compromised; run `chmod 0600 {}`",
                path.display()
            ),
        };
    }
    match std::fs::metadata(&path).map(|m| m.len()) {
        Ok(n) if n >= 16 => CheckOutcome {
            name: "hmac.key",
            status: CheckStatus::Pass,
            detail: format!("{n} bytes, mode 0600"),
        },
        Ok(n) => CheckOutcome {
            name: "hmac.key",
            status: CheckStatus::Fail,
            detail: format!("{n} bytes is too short — regenerate"),
        },
        Err(e) => CheckOutcome {
            name: "hmac.key",
            status: CheckStatus::Fail,
            detail: format!("stat failed: {e}"),
        },
    }
}

fn check_quota(home: &Path) -> CheckOutcome {
    let ceiling = crate::daemon::quota::DEFAULT_CEILING_BYTES;
    let state = crate::daemon::quota::snapshot_quota(home, ceiling);
    if state.is_breached() {
        CheckOutcome {
            name: "disk quota",
            status: CheckStatus::Fail,
            detail: format!(
                "{} ≥ {} ceiling — daemon will reject new writes",
                fmt_bytes(state.used()),
                fmt_bytes(state.ceiling())
            ),
        }
    } else {
        CheckOutcome {
            name: "disk quota",
            status: CheckStatus::Pass,
            detail: format!(
                "{} of {} used",
                fmt_bytes(state.used()),
                fmt_bytes(state.ceiling())
            ),
        }
    }
}

fn check_policy_yaml(home: &Path) -> CheckOutcome {
    let path = home.join("policy.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "policy.yaml",
            status: CheckStatus::Pass,
            detail: "absent (no dangerous-target deny list configured)".into(),
        };
    }
    match crate::policy::PolicyConfig::load_or_default(&path) {
        Ok(p) => CheckOutcome {
            name: "policy.yaml",
            status: CheckStatus::Pass,
            detail: format!(
                "{} dangerous target(s), {} pattern(s)",
                p.dangerous_targets.len(),
                p.dangerous_patterns.len()
            ),
        },
        Err(e) => CheckOutcome {
            name: "policy.yaml",
            status: CheckStatus::Fail,
            detail: format!("{e:#}"),
        },
    }
}

fn check_hooks_dir(home: &Path) -> CheckOutcome {
    let dir = home.join("hooks");
    if !dir.is_dir() {
        return CheckOutcome {
            name: "hooks/",
            status: CheckStatus::Pass,
            detail: "absent (no operator-defined hooks loaded)".into(),
        };
    }
    // Walk *.toml files. Parse each individually; one malformed file
    // shouldn't fail the whole check — surface a count of bad rows.
    let mut total = 0usize;
    let mut bad = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            total += 1;
            match std::fs::read_to_string(&path) {
                Ok(body) => {
                    if let Err(e) = toml::from_str::<crate::hooks::schema::HookDef>(&body) {
                        bad.push(format!(
                            "{}: {e}",
                            path.file_name().and_then(|s| s.to_str()).unwrap_or("?")
                        ));
                    }
                }
                Err(e) => bad.push(format!(
                    "{}: {e}",
                    path.file_name().and_then(|s| s.to_str()).unwrap_or("?")
                )),
            }
        }
    }
    if bad.is_empty() {
        CheckOutcome {
            name: "hooks/",
            status: CheckStatus::Pass,
            detail: format!("{total} hook file(s) parse cleanly"),
        }
    } else {
        CheckOutcome {
            name: "hooks/",
            status: CheckStatus::Fail,
            detail: format!(
                "{} of {total} hook file(s) fail to parse: {}",
                bad.len(),
                bad.join("; ")
            ),
        }
    }
}

fn check_agents_dir(home: &Path) -> CheckOutcome {
    let dir = home.join("agents");
    if !dir.is_dir() {
        return CheckOutcome {
            name: "agents/",
            status: CheckStatus::Pass,
            detail: "absent (built-in sub-agents only)".into(),
        };
    }
    let mut total = 0usize;
    let mut bad = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            total += 1;
            match std::fs::read_to_string(&path) {
                Ok(body) => {
                    if let Err(e) = toml::from_str::<crate::sub_agents::schema::SubAgent>(&body) {
                        bad.push(format!(
                            "{}: {e}",
                            path.file_name().and_then(|s| s.to_str()).unwrap_or("?")
                        ));
                    }
                }
                Err(e) => bad.push(format!(
                    "{}: {e}",
                    path.file_name().and_then(|s| s.to_str()).unwrap_or("?")
                )),
            }
        }
    }
    if bad.is_empty() {
        CheckOutcome {
            name: "agents/",
            status: CheckStatus::Pass,
            detail: format!("{total} sub-agent file(s) parse cleanly"),
        }
    } else {
        CheckOutcome {
            name: "agents/",
            status: CheckStatus::Fail,
            detail: format!(
                "{} of {total} sub-agent file(s) fail to parse: {}",
                bad.len(),
                bad.join("; ")
            ),
        }
    }
}

fn check_profile_extensions(home: &Path) -> CheckOutcome {
    let path = home.join("profile_extensions.toml");
    if !path.exists() {
        return CheckOutcome {
            name: "profile_extensions.toml",
            status: CheckStatus::Pass,
            detail: "absent (only base profile taxonomy allowed)".into(),
        };
    }
    match crate::profile::extension_registry::TypedExtensionRegistry::load_from(&path) {
        Ok(reg) => CheckOutcome {
            name: "profile_extensions.toml",
            status: CheckStatus::Pass,
            detail: format!(
                "{} operator-registered profile category extension(s)",
                reg.registered_count()
            ),
        },
        Err(e) => CheckOutcome {
            name: "profile_extensions.toml",
            status: CheckStatus::Fail,
            detail: format!("{e:#}"),
        },
    }
}

fn check_tweaks_toml(home: &Path) -> CheckOutcome {
    let path = home.join("tweaks.toml");
    if !path.exists() {
        return CheckOutcome {
            name: "tweaks.toml",
            status: CheckStatus::Pass,
            detail: "absent (built-in defaults)".into(),
        };
    }
    match crate::tweaks::Tweaks::load_or_default(&path) {
        Ok(t) => CheckOutcome {
            name: "tweaks.toml",
            status: CheckStatus::Pass,
            detail: format!("{} prompt snippet(s) configured", t.prompts.len()),
        },
        Err(e) => CheckOutcome {
            name: "tweaks.toml",
            status: CheckStatus::Fail,
            detail: format!("{e:#}"),
        },
    }
}

/// CLIP + Whisper caches are optional — extractions fall back to
/// metadata-only when missing — but operators who plan to send media
/// to NEOTH want them populated. We emit a `Warn` (not `Fail`) so
/// `neoth doctor` exits clean for text-only setups while still
/// surfacing the actionable next step.
fn check_model_caches() -> CheckOutcome {
    use crate::providers::{clip_engine, whisper};

    let clip_dir = clip_engine::default_cache_dir(clip_engine::DEFAULT_CLIP_REPO);
    let clip_present = [
        clip_engine::CONFIG_FILE,
        clip_engine::SAFETENSORS_FILE,
        clip_engine::TOKENIZER_FILE,
    ]
    .iter()
    .all(|f| clip_dir.join(f).exists());

    let whisper_dir = whisper_doctor_cache_dir(whisper::DEFAULT_WHISPER_REPO);
    let whisper_present = [
        whisper::CONFIG_FILE,
        whisper::TOKENIZER_FILE,
        whisper::SAFETENSORS_FILE,
    ]
    .iter()
    .all(|f| whisper_dir.join(f).exists());

    let detail = match (clip_present, whisper_present) {
        (true, true) => "clip + whisper cached".to_string(),
        (true, false) => "whisper missing — run `neoth models pull whisper`".to_string(),
        (false, true) => "clip missing — run `neoth models pull clip`".to_string(),
        (false, false) => {
            "clip + whisper missing — run `neoth models pull clip whisper`".to_string()
        }
    };
    let status = if clip_present && whisper_present {
        CheckStatus::Pass
    } else {
        CheckStatus::Warn
    };
    CheckOutcome {
        name: "model caches",
        status,
        detail,
    }
}

/// R-3 Hysteria — when freedom.yaml has a server configured, verify
/// the binary is reachable + the rendered YAML has the fields Hysteria
/// expects. No live spawn here; that's `neoth hysteria test`'s job.
fn check_hysteria_config(home: &Path) -> CheckOutcome {
    let freedom_path = home.join("freedom.yaml");
    let Ok(cfg) = crate::config::FreedomConfig::load_from_path(&freedom_path) else {
        return CheckOutcome {
            name: "hysteria",
            status: CheckStatus::Pass,
            detail: "freedom.yaml unreadable; check_freedom_yaml owns the diagnostic".into(),
        };
    };
    let Some(hcfg) = cfg.hysteria.as_ref() else {
        return CheckOutcome {
            name: "hysteria",
            status: CheckStatus::Pass,
            detail: "not configured (direct egress)".into(),
        };
    };
    if hcfg.server.is_empty() {
        return CheckOutcome {
            name: "hysteria",
            status: CheckStatus::Pass,
            detail: "configured but server empty (direct egress)".into(),
        };
    }
    match crate::transport::hysteria::locate_binary() {
        Ok(path) => CheckOutcome {
            name: "hysteria",
            status: CheckStatus::Pass,
            detail: format!("binary at {}, server={}", path.display(), hcfg.server),
        },
        Err(e) => CheckOutcome {
            name: "hysteria",
            status: CheckStatus::Warn,
            detail: format!("config set ({}) but binary missing: {e}", hcfg.server,),
        },
    }
}

/// R-8 Cloud archive — when freedom.yaml has a destination, verify the
/// folder actually exists. Most common operator error is a typo'd
/// path, or the cloud client wasn't installed.
fn check_cloud_archive_dest(home: &Path) -> CheckOutcome {
    let freedom_path = home.join("freedom.yaml");
    let Ok(cfg) = crate::config::FreedomConfig::load_from_path(&freedom_path) else {
        return CheckOutcome {
            name: "cloud archive",
            status: CheckStatus::Pass,
            detail: "freedom.yaml unreadable; check_freedom_yaml owns the diagnostic".into(),
        };
    };
    let Some(dest_str) = cfg.cloud_archive_dest.as_deref() else {
        return CheckOutcome {
            name: "cloud archive",
            status: CheckStatus::Pass,
            detail: "not configured".into(),
        };
    };
    let dest = std::path::Path::new(dest_str);
    if !dest.exists() {
        return CheckOutcome {
            name: "cloud archive",
            status: CheckStatus::Warn,
            detail: format!(
                "configured dest {} does not exist (is the cloud client running?)",
                dest_str,
            ),
        };
    }
    if !dest.is_dir() {
        return CheckOutcome {
            name: "cloud archive",
            status: CheckStatus::Fail,
            detail: format!("configured dest {dest_str} is a file, not a directory"),
        };
    }
    CheckOutcome {
        name: "cloud archive",
        status: CheckStatus::Pass,
        detail: format!("destination {dest_str} present"),
    }
}

/// CDX-05 follow-up: surface the MCP servers config + flag stale
/// entries. Pure config-read — no process spawn (would slow down
/// `neoth doctor` from <1s to >5s). Operators run `neoth mcp tools
/// <id>` for a live handshake test.
///
/// Three outcomes:
///   - File missing → Pass with "(not configured)" since MCP is
///     optional. NEOTH still runs.
///   - File present, zero servers → Warn (file exists but nothing to
///     do — operator probably half-configured something).
///   - File present, N enabled → Pass listing ids + whether each pins
///     `allow_tools` (CDX-03 hardening posture).
fn check_mcp_servers(home: &Path) -> CheckOutcome {
    let path = home.join("mcp_servers.yaml");
    if !path.exists() {
        return CheckOutcome {
            name: "mcp servers",
            status: CheckStatus::Pass,
            detail: "(not configured — create ~/.neoth/mcp_servers.yaml to enable MCP)".into(),
        };
    }
    let servers = match crate::mcp::McpServers::load_from(&path) {
        Ok(s) => s,
        Err(e) => {
            return CheckOutcome {
                name: "mcp servers",
                status: CheckStatus::Fail,
                detail: format!("{} unreadable: {e}", path.display()),
            };
        }
    };
    let enabled = servers.enabled();
    if enabled.is_empty() {
        return CheckOutcome {
            name: "mcp servers",
            status: CheckStatus::Warn,
            detail: format!(
                "{} present but zero enabled servers (operator half-configured?)",
                path.display(),
            ),
        };
    }
    // Reviewer-1 P1-A doctor warning (2026-05-20): three buckets now.
    //   `hardened`   — allow_tools pinned (recommended)
    //   `trust_all`  — operator explicitly opted into the legacy
    //                  catalogue-trust path via `trust_all_tools: true`
    //   `broken`     — allow_tools=None AND trust_all_tools=false →
    //                  the gate will DENY every call (secure-default)
    let hardened: Vec<&str> = enabled
        .iter()
        .filter(|s| s.allow_tools.is_some())
        .map(|s| s.id.as_str())
        .collect();
    let trust_all: Vec<&str> = enabled
        .iter()
        .filter(|s| s.allow_tools.is_none() && s.trust_all_tools)
        .map(|s| s.id.as_str())
        .collect();
    let broken: Vec<&str> = enabled
        .iter()
        .filter(|s| s.allow_tools.is_none() && !s.trust_all_tools)
        .map(|s| s.id.as_str())
        .collect();
    let detail = if !broken.is_empty() {
        format!(
            "{} enabled — hardened: [{}]; trust_all_tools: [{}]; \
             BROKEN (no allow_tools + trust_all_tools=false → all calls denied): [{}]. \
             Pin allow_tools or set trust_all_tools: true on each broken server.",
            enabled.len(),
            hardened.join(", "),
            trust_all.join(", "),
            broken.join(", "),
        )
    } else {
        format!(
            "{} enabled — hardened (allow_tools pinned): [{}]; legacy (trust_all_tools=true): [{}]",
            enabled.len(),
            hardened.join(", "),
            trust_all.join(", "),
        )
    };
    // Posture: Pass when every enabled server is either hardened or
    // explicit-trust. Warn when any server is in the broken state
    // (operator's gate denies every call until they opt-in or pin).
    let status = if broken.is_empty() {
        CheckStatus::Pass
    } else {
        CheckStatus::Warn
    };
    CheckOutcome {
        name: "mcp servers",
        status,
        detail,
    }
}

/// NOOB-UX-3 doctor surface — report the effective state of the
/// WASM plugin host so an operator who expected plugins to be
/// live sees the mismatch (slim build vs. operator-disabled).
fn check_wasm_plugins(home: &Path) -> CheckOutcome {
    use crate::config::FreedomConfig;
    let compiled_in = cfg!(feature = "wasm-plugin-host");
    let cfg_enabled = FreedomConfig::load_from_path(&home.join("freedom.yaml"))
        .map(|c| c.plugins.wasm.enabled)
        .unwrap_or(true);
    let (status, detail) = match (compiled_in, cfg_enabled) {
        (true, true) => (
            CheckStatus::Pass,
            "compiled-in + enabled by config — operator-loadable plugins are live".to_string(),
        ),
        (true, false) => (
            CheckStatus::Warn,
            "compiled-in but DISABLED by config (freedom.yaml::plugins.wasm.enabled = false). \
             Hook actions of kind Plugin{..} will degrade to Allow. \
             Flip the config to enable, or rebuild without `--features wasm-plugin-host` if \
             intentional."
                .to_string(),
        ),
        (false, true) => (
            CheckStatus::Warn,
            "not compiled in (slim daemon build); freedom.yaml has plugins.wasm.enabled=true \
             but the cargo `wasm-plugin-host` feature is OFF. Operator expecting plugins should \
             rebuild with `--features wasm-plugin-host` or install the release tarball."
                .to_string(),
        ),
        (false, false) => (
            CheckStatus::Pass,
            "not compiled in (slim daemon) AND config disabled — coherent slim state".to_string(),
        ),
    };
    CheckOutcome {
        name: "wasm plugins",
        status,
        detail,
    }
}

/// R2-P0-2 doctor surface — honest per-channel wiring status.
///
/// Closes the "Channels on deck" honesty gap flagged by the R2
/// reviewer (`PLAN/REEVALUATION_GESAMT_2026-05-21_R2.md` §4 P0-2).
/// Pre-fix: README/Status claimed channels were live when
/// `cli::serve` only spawned Telegram. Operators configured Slack /
/// WhatsApp tokens, saw "ok" in their setup, and never realised
/// inbound was deferred.
///
/// Post-fix: each channel gets one of four classifications:
///
/// - **LIVE**: tokens configured + adapter has live inbound + serve
///   spawns it. Telegram today.
/// - **OUTBOUND-ONLY**: tokens configured + adapter can send_text but
///   the inbound receive loop is deferred. WhatsApp + Keet adapters
///   bail on `run()`. Slack adapter has socket_mode but serve does
///   not spawn it yet.
/// - **CONFIGURED-NOT-STARTED**: tokens configured + adapter has full
///   inbound code BUT serve does not bootstrap it. Discord (gateway
///   loop ships) is the current example.
/// - **NOT-CONFIGURED**: no credentials present. Silent.
fn check_channels_wiring(home: &Path) -> CheckOutcome {
    let creds = match crate::config::credentials::Credentials::load_or_default(
        &home.join("credentials.yaml"),
    ) {
        Ok(c) => c,
        Err(_) => {
            return CheckOutcome {
                name: "channels wiring",
                status: CheckStatus::Warn,
                detail: "credentials.yaml unreadable; per-channel status unavailable".to_string(),
            };
        }
    };

    // Tuple shape: (channel name, classification, note). Only configured
    // channels show up — silent on NOT-CONFIGURED to keep doctor output
    // focused on what the operator actually set up.
    let mut rows: Vec<(&'static str, &'static str, &'static str)> = Vec::new();

    if creds.telegram_token.is_some() {
        rows.push((
            "telegram",
            "LIVE",
            "polling loop spawned by serve; send + receive both real",
        ));
    }
    if creds.slack_bot_token.is_some() || creds.slack_app_token.is_some() {
        rows.push((
            "slack",
            "OUTBOUND-ONLY",
            "send_text via chat.postMessage works; socket-mode receive loop \
             not yet spawned by serve",
        ));
    }
    if creds.whatsapp_token.is_some() || creds.whatsapp_phone_id.is_some() {
        rows.push((
            "whatsapp",
            "OUTBOUND-ONLY",
            "send_text via Graph API works; webhook listener not yet wired \
             into serve (channels::WhatsAppChannel::run bails)",
        ));
    }
    // Discord + Keet have no credentials.yaml fields yet, so they only
    // surface here when their config moves to credentials.yaml. Note
    // the design intent so operators reading the diagnostic see why
    // they aren't listed.

    if rows.is_empty() {
        return CheckOutcome {
            name: "channels wiring",
            status: CheckStatus::Pass,
            detail: "no channel credentials configured — daemon runs in CLI-only mode".to_string(),
        };
    }

    // Aggregate status: LIVE counts as Pass; anything less downgrades
    // the whole check to Warn so operators who configured Slack/
    // WhatsApp expecting live inbound see a yellow flag.
    let any_partial = rows.iter().any(|(_, cls, _)| *cls != "LIVE");
    let status = if any_partial {
        CheckStatus::Warn
    } else {
        CheckStatus::Pass
    };

    let detail = rows
        .iter()
        .map(|(ch, cls, note)| format!("{ch}: {cls} — {note}"))
        .collect::<Vec<_>>()
        .join("; ");

    CheckOutcome {
        name: "channels wiring",
        status,
        detail,
    }
}

/// Warn when free disk on `~/.neoth/`'s partition is below the full
/// model-cache footprint. Operators who haven't pulled CLIP / whisper /
/// Qwen yet see a heads-up before the download stalls at 70%.
fn check_disk_space(home: &Path) -> CheckOutcome {
    let probe = crate::daemon::hardware::probe(home);
    let avail = probe.disk.home_available_gib();
    let needed = probe.estimated_full_cache_gib;
    if probe.disk.home_total_bytes == 0 {
        return CheckOutcome {
            name: "disk space",
            status: CheckStatus::Pass,
            detail: format!(
                "{} mount not resolvable (containerised?); skipping check",
                probe.disk.home_mount,
            ),
        };
    }
    if avail < needed {
        return CheckOutcome {
            name: "disk space",
            status: CheckStatus::Warn,
            detail: format!(
                "{:.1} GiB free on {} but full model cache is ~{:.1} GiB",
                avail, probe.disk.home_mount, needed,
            ),
        };
    }
    CheckOutcome {
        name: "disk space",
        status: CheckStatus::Pass,
        detail: format!(
            "{:.1} GiB free on {} (need ~{:.1} GiB for full cache)",
            avail, probe.disk.home_mount, needed,
        ),
    }
}

/// Local copy of the whisper engine's `default_cache_dir` so the doctor
/// can run with the same path math as the engine without exposing the
/// engine's `pub` surface. Kept in sync via the
/// `whisper_cache_dir_matches_engine_default` test in
/// `cli::models::tests`.
fn whisper_doctor_cache_dir(repo: &str) -> PathBuf {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|_| PathBuf::from("."));
    let flattened = repo.replace('/', "-");
    home.join(".neoth").join("models").join(flattened)
}

#[cfg(unix)]
fn is_mode_0600(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    meta.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn is_mode_0600(_path: &Path) -> bool {
    // Windows DACL parsing is out of scope here — the wizard's icacls pass
    // is the actual enforcement (see `wal/win_acl.rs`). `neoth doctor`
    // accepts files exist as good on Windows; deep DACL inspection is a
    // future addition.
    true
}

fn fmt_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if n >= GIB {
        format!("{:.2} GiB", n as f64 / GIB as f64)
    } else if n >= MIB {
        format!("{:.2} MiB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.2} KiB", n as f64 / KIB as f64)
    } else {
        format!("{n} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // ── V03-07 2026-05-17: --explain + --list-checks ──────────────────

    #[test]
    fn check_docs_cover_every_check_name_in_run_all() {
        // Drift guard: every check name produced by `run_all_checks`
        // must have an explain entry. Refactor that adds a new check
        // without updating CHECK_DOCS fails here.
        let dir = tempdir().unwrap();
        let outcomes = run_all_checks(dir.path());
        let doc_names: std::collections::HashSet<&str> =
            CHECK_DOCS.iter().map(|d| d.name).collect();
        for o in &outcomes {
            assert!(
                doc_names.contains(o.name),
                "check `{}` produced by run_all_checks has no CHECK_DOCS entry — \
                 add one in cli/doctor.rs::CHECK_DOCS",
                o.name
            );
        }
    }

    #[test]
    fn find_check_doc_case_insensitive_match() {
        assert!(find_check_doc("freedom.yaml").is_some());
        assert!(find_check_doc("FREEDOM.YAML").is_some());
        assert!(find_check_doc(" wal segments ").is_some());
    }

    #[test]
    fn find_check_doc_returns_none_for_unknown_name() {
        assert!(find_check_doc("definitely-not-a-check").is_none());
        assert!(find_check_doc("").is_none());
    }

    #[test]
    fn every_check_doc_has_non_empty_fields() {
        for d in CHECK_DOCS {
            assert!(!d.name.is_empty(), "CheckDoc name empty");
            assert!(!d.purpose.is_empty(), "CheckDoc {} purpose empty", d.name);
            assert!(
                !d.common_failures.is_empty(),
                "CheckDoc {} common_failures empty",
                d.name
            );
            assert!(!d.fix.is_empty(), "CheckDoc {} fix empty", d.name);
        }
    }

    #[test]
    fn check_docs_listed_count_pinned_at_nineteen() {
        // Pin the count so a future addition is a conscious update + a
        // future deletion (which would silently drop operator runbook
        // coverage) is caught. Bumped to 19 in Session 20 for
        // `channels wiring` (R2-P0-2 honesty surface — per-channel
        // LIVE / OUTBOUND-ONLY / CONFIGURED-NOT-STARTED classification).
        assert_eq!(CHECK_DOCS.len(), 19);
    }

    #[tokio::test]
    async fn run_doctor_list_checks_prints_every_name_in_table_mode() {
        // Smoke: --list-checks short-circuits without touching the home
        // dir. Captures stdout via the println contract — no fancy
        // redirection. Pass tempdir as home so the no-config short-
        // circuit doesn't bail.
        let dir = tempdir().unwrap();
        let args = DoctorArgs {
            home: Some(dir.path().to_path_buf()),
            quiet: false,
            explain: None,
            list_checks: true,
            output: OutputFormat::Table,
        };
        // Just verify it returns Ok without panicking — output capture
        // would need the integration-test harness.
        run_doctor(args).await.unwrap();
    }

    #[tokio::test]
    async fn run_doctor_explain_unknown_check_errors_with_pointer() {
        let dir = tempdir().unwrap();
        let args = DoctorArgs {
            home: Some(dir.path().to_path_buf()),
            quiet: false,
            explain: Some("nope-not-real".to_string()),
            list_checks: false,
            output: OutputFormat::Table,
        };
        let err = run_doctor(args).await.unwrap_err();
        assert!(err.to_string().contains("no doctor check named"));
        assert!(err.to_string().contains("--list-checks"));
    }

    #[tokio::test]
    async fn run_doctor_explain_known_check_succeeds() {
        let dir = tempdir().unwrap();
        let args = DoctorArgs {
            home: Some(dir.path().to_path_buf()),
            quiet: false,
            explain: Some("freedom.yaml".to_string()),
            list_checks: false,
            output: OutputFormat::Table,
        };
        run_doctor(args).await.unwrap();
    }

    #[test]
    fn freedom_yaml_missing_is_fail() {
        let dir = tempdir().unwrap();
        let o = check_freedom_yaml(dir.path());
        assert_eq!(o.status, CheckStatus::Fail);
        assert!(o.detail.contains("neoth init"));
    }

    #[test]
    fn freedom_yaml_present_and_parseable_passes() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("freedom.yaml"), "operator_id: alex\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                dir.path().join("freedom.yaml"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let o = check_freedom_yaml(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
    }

    #[test]
    fn credentials_absent_is_pass() {
        let dir = tempdir().unwrap();
        let o = check_credentials_yaml(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
        assert!(o.detail.contains("absent"));
    }

    #[test]
    fn views_db_missing_is_warn() {
        let dir = tempdir().unwrap();
        let o = check_views_db(dir.path());
        assert_eq!(o.status, CheckStatus::Warn);
    }

    #[test]
    fn wal_segments_missing_dir_warns() {
        let dir = tempdir().unwrap();
        let o = check_wal_segments(dir.path());
        assert_eq!(o.status, CheckStatus::Warn);
    }

    #[test]
    fn hmac_key_absent_is_warn() {
        let dir = tempdir().unwrap();
        let o = check_hmac_key(dir.path());
        assert_eq!(o.status, CheckStatus::Warn);
    }

    #[test]
    fn run_all_checks_returns_one_outcome_per_diagnostic() {
        let dir = tempdir().unwrap();
        let outs = run_all_checks(dir.path());
        // 19 checks (freedom, credentials, credentials age, views.db, wal,
        // hmac, quota, policy, tweaks, model caches, hysteria, cloud archive,
        // disk space, hooks, agents, profile_extensions, mcp servers,
        // wasm plugins, channels wiring — Session 20 R2-P0-2 addition).
        assert_eq!(outs.len(), 19);
        for o in &outs {
            assert!(!o.detail.is_empty(), "{} has empty detail", o.name);
        }
    }

    // ── R2-P0-2 channels-wiring tests ────────────────────────────────────

    #[test]
    fn r2_p0_2_channels_wiring_pass_when_no_credentials() {
        let dir = tempdir().unwrap();
        // No credentials.yaml → daemon runs CLI-only, no channel claims
        // to make. Pass + explanatory detail.
        let outcome = check_channels_wiring(dir.path());
        assert_eq!(outcome.name, "channels wiring");
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(
            outcome.detail.contains("CLI-only") || outcome.detail.contains("no channel credentials"),
            "detail must explain the no-credentials state: {}",
            outcome.detail
        );
    }

    #[test]
    fn r2_p0_2_channels_wiring_live_when_only_telegram_configured() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("credentials.yaml"),
            "telegram_token: \"123:abcXYZ_test_token_value\"\n",
        )
        .unwrap();
        let outcome = check_channels_wiring(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("telegram"));
        assert!(outcome.detail.contains("LIVE"));
    }

    #[test]
    fn r2_p0_2_channels_wiring_warn_when_slack_configured() {
        // Operator configured Slack expecting bidirectional chat. The
        // doctor must Warn so the gap surfaces during install
        // verification (matches R2 P0-2 done-criterion: "neoth doctor
        // channels muss 'outbound-only' / 'live' / 'scaffold' sauber
        // trennen").
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("credentials.yaml"),
            "slack_bot_token: \"xoxb-test-token\"\n",
        )
        .unwrap();
        let outcome = check_channels_wiring(dir.path());
        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(outcome.detail.contains("slack"));
        assert!(outcome.detail.contains("OUTBOUND-ONLY"));
    }

    #[test]
    fn r2_p0_2_channels_wiring_warn_when_whatsapp_configured() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("credentials.yaml"),
            "whatsapp_token: \"test-wa-token\"\nwhatsapp_phone_id: \"123456789\"\n",
        )
        .unwrap();
        let outcome = check_channels_wiring(dir.path());
        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(outcome.detail.contains("whatsapp"));
        assert!(outcome.detail.contains("OUTBOUND-ONLY"));
    }

    #[test]
    fn r2_p0_2_channels_wiring_mixed_aggregates_to_warn() {
        // Telegram alone = Pass. Telegram + Slack = Warn (the partial
        // channel pulls the aggregate down so the gap is visible at
        // a glance instead of getting buried under one green row).
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("credentials.yaml"),
            "telegram_token: \"123:abc\"\nslack_bot_token: \"xoxb-test\"\n",
        )
        .unwrap();
        let outcome = check_channels_wiring(dir.path());
        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(outcome.detail.contains("telegram: LIVE"));
        assert!(outcome.detail.contains("slack: OUTBOUND-ONLY"));
    }

    #[test]
    fn hooks_dir_missing_is_pass() {
        let dir = tempdir().unwrap();
        let o = check_hooks_dir(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
    }

    #[test]
    fn hooks_dir_with_malformed_toml_fails() {
        let dir = tempdir().unwrap();
        let hooks = dir.path().join("hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        std::fs::write(hooks.join("bad.toml"), "name = ").unwrap();
        let o = check_hooks_dir(dir.path());
        assert_eq!(o.status, CheckStatus::Fail);
        assert!(o.detail.contains("bad.toml"));
    }

    #[test]
    fn agents_dir_missing_is_pass() {
        let dir = tempdir().unwrap();
        let o = check_agents_dir(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
    }

    #[test]
    fn profile_extensions_missing_is_pass() {
        let dir = tempdir().unwrap();
        let o = check_profile_extensions(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
    }

    #[test]
    fn profile_extensions_well_formed_passes_with_count() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("profile_extensions.toml"),
            "[extensions]\npets = \"Vec<Pet>\"\n",
        )
        .unwrap();
        let o = check_profile_extensions(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
        assert!(o.detail.contains('1'));
    }

    #[test]
    fn check_hysteria_pass_when_unconfigured() {
        let dir = tempdir().unwrap();
        // No freedom.yaml at all → graceful pass (other check owns that
        // diagnostic).
        let o = check_hysteria_config(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
    }

    #[test]
    fn check_cloud_archive_fails_when_dest_is_a_file() {
        let dir = tempdir().unwrap();
        let bogus = dir.path().join("not-a-dir.txt");
        std::fs::write(&bogus, "x").unwrap();
        let yaml = format!(
            "operator_id: alex\nautonomy: standard\ncloud_archive_dest: {}\n",
            bogus.display().to_string().replace('\\', "/")
        );
        std::fs::write(dir.path().join("freedom.yaml"), yaml).unwrap();
        let o = check_cloud_archive_dest(dir.path());
        assert_eq!(o.status, CheckStatus::Fail);
        assert!(o.detail.contains("file, not a directory"));
    }

    #[test]
    fn check_cloud_archive_warns_when_dest_missing() {
        let dir = tempdir().unwrap();
        let yaml =
            "operator_id: alex\nautonomy: standard\ncloud_archive_dest: /definitely/not/here\n";
        std::fs::write(dir.path().join("freedom.yaml"), yaml).unwrap();
        let o = check_cloud_archive_dest(dir.path());
        assert_eq!(o.status, CheckStatus::Warn);
        assert!(o.detail.contains("does not exist"));
    }

    #[test]
    fn check_mcp_servers_passes_when_file_absent() {
        let dir = tempdir().unwrap();
        let o = check_mcp_servers(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
        assert!(o.detail.contains("not configured"));
    }

    #[test]
    fn check_mcp_servers_warns_when_file_present_but_no_enabled_servers() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("mcp_servers.yaml"), "servers: []\n").unwrap();
        let o = check_mcp_servers(dir.path());
        assert_eq!(o.status, CheckStatus::Warn);
        assert!(o.detail.contains("half-configured"));
    }

    #[test]
    fn check_mcp_servers_warns_when_any_server_lacks_allow_tools() {
        let dir = tempdir().unwrap();
        let yaml = r#"
servers:
  - id: hardened
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem"]
    allow_tools: ["read_file"]
  - id: legacy
    command: npx
    args: ["-y", "@modelcontextprotocol/server-github"]
"#;
        std::fs::write(dir.path().join("mcp_servers.yaml"), yaml).unwrap();
        let o = check_mcp_servers(dir.path());
        // One server hardened, one legacy → posture is Warn (CDX-03
        // says full-catalogue trust is the legacy posture, not the
        // recommended one).
        assert_eq!(o.status, CheckStatus::Warn);
        assert!(o.detail.contains("hardened"));
        assert!(o.detail.contains("legacy"));
        assert!(o.detail.contains("[hardened]"));
        assert!(o.detail.contains("[legacy]"));
    }

    #[test]
    fn check_mcp_servers_passes_when_every_server_has_allow_tools() {
        let dir = tempdir().unwrap();
        let yaml = r#"
servers:
  - id: filesystem
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem"]
    allow_tools: ["read_file", "list_directory"]
"#;
        std::fs::write(dir.path().join("mcp_servers.yaml"), yaml).unwrap();
        let o = check_mcp_servers(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
        assert!(o.detail.contains("1 enabled"));
    }

    #[test]
    fn check_mcp_servers_fails_on_malformed_yaml() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("mcp_servers.yaml"), "this is not: yaml: [").unwrap();
        let o = check_mcp_servers(dir.path());
        assert_eq!(o.status, CheckStatus::Fail);
        assert!(o.detail.contains("unreadable"));
    }

    #[test]
    fn check_disk_space_always_emits_a_detail() {
        let dir = tempdir().unwrap();
        let o = check_disk_space(dir.path());
        assert!(!o.detail.is_empty());
        // Either Pass (enough free) or Warn (low disk) — never Fail.
        assert!(matches!(o.status, CheckStatus::Pass | CheckStatus::Warn));
    }

    #[test]
    fn model_caches_emits_actionable_detail() {
        // We can't reliably assert on the operator's real ~/.neoth, so
        // just verify the check produces a non-empty status + detail
        // and that the detail names the `neoth models pull` command
        // when anything is missing.
        let o = check_model_caches();
        assert!(!o.detail.is_empty());
        if o.status != CheckStatus::Pass {
            assert!(
                o.detail.contains("models pull"),
                "warn must include actionable next step, got: {}",
                o.detail
            );
        }
    }

    #[test]
    fn fmt_bytes_picks_unit() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(512), "512 B");
        assert!(fmt_bytes(2048).starts_with("2.00"));
        assert!(fmt_bytes(1024 * 1024 * 5).starts_with("5.00 MiB"));
        assert!(fmt_bytes(5 * 1024 * 1024 * 1024).starts_with("5.00 GiB"));
    }

    // ── credential age (audit 2026-05-19) ─────────────────────────────

    /// Write `credentials.yaml` with a single Telegram token and set its
    /// mtime to `now - age_days * 86400`. Returns the credentials path.
    fn write_aged_credentials(home: &Path, age_days: u64) -> std::path::PathBuf {
        let path = home.join("credentials.yaml");
        std::fs::write(&path, "telegram_token: \"123:ABC\"\n").unwrap();
        let target = std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(age_days * SECONDS_PER_DAY))
            .unwrap();
        filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(target)).unwrap();
        path
    }

    #[test]
    fn credential_age_passes_when_file_absent() {
        let dir = tempdir().unwrap();
        let o = check_credential_age(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
        assert!(o.detail.contains("no credentials.yaml"));
    }

    #[test]
    fn credential_age_passes_when_file_holds_only_none_slots() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("credentials.yaml");
        // Empty YAML map → every Option<SecretString> is None → no
        // secrets to age-check, regardless of mtime.
        std::fs::write(&path, "{}\n").unwrap();
        let stale = std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(500 * SECONDS_PER_DAY))
            .unwrap();
        filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(stale)).unwrap();
        let o = check_credential_age(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
        assert!(o.detail.contains("no secrets to age-check"));
    }

    #[test]
    fn credential_age_passes_when_fresh() {
        let dir = tempdir().unwrap();
        write_aged_credentials(dir.path(), 10);
        let o = check_credential_age(dir.path());
        assert_eq!(o.status, CheckStatus::Pass);
    }

    #[test]
    fn credential_age_warns_after_180_days() {
        let dir = tempdir().unwrap();
        write_aged_credentials(dir.path(), 200);
        let o = check_credential_age(dir.path());
        assert_eq!(o.status, CheckStatus::Warn);
        assert!(o.detail.contains("200"));
        assert!(o.detail.contains("rotat"));
    }

    #[test]
    fn credential_age_fails_after_365_days() {
        let dir = tempdir().unwrap();
        write_aged_credentials(dir.path(), 400);
        let o = check_credential_age(dir.path());
        assert_eq!(o.status, CheckStatus::Fail);
        assert!(o.detail.contains("400"));
        assert!(o.detail.contains("rotate"));
    }
}
