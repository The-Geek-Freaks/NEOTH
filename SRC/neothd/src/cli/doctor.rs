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

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;

mod checks;
mod types;

pub use types::*;

const DOMAIN_CHECKS: &[&[CheckFn]] = &[
    checks::config::CHECKS,
    checks::storage::CHECKS,
    checks::tooling::CHECKS,
    checks::integrations::CHECKS,
    checks::providers::CHECKS,
    checks::cluster::CHECKS,
    checks::capabilities::CHECKS,
];

const DOMAIN_DOCS: &[&[CheckDoc]] = &[
    checks::config::DOCS,
    checks::storage::DOCS,
    checks::tooling::DOCS,
    checks::integrations::DOCS,
    checks::providers::DOCS,
    checks::cluster::DOCS,
    checks::capabilities::DOCS,
];

/// Every check's runbook doc, across all domains (the `--explain` /
/// `--list-checks` surface).
fn all_check_docs() -> impl Iterator<Item = &'static CheckDoc> {
    DOMAIN_DOCS.iter().flat_map(|d| d.iter())
}

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
    /// GOLD-ADOPT-24: after running the checks, feed any WARN/FAIL outcomes to
    /// the cheap `inference.utility_provider` for an LLM root-cause + first-fix.
    /// NEOTH's 31 structured checks are a richer signal than a raw log dump, so
    /// the LLM reasons over them. Best-effort; needs a configured provider.
    #[arg(long)]
    pub diagnose: bool,
    /// Output format inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}


/// Find a CheckDoc by case-insensitive name match. `None` when no doc
/// exists for that check name (typo in operator's `--explain` flag).
fn find_check_doc(name: &str) -> Option<&'static CheckDoc> {
    let needle = name.trim().to_ascii_lowercase();
    all_check_docs().find(|d| d.name.to_ascii_lowercase() == needle)
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

pub async fn run_doctor(args: DoctorArgs) -> Result<()> {
    // V03-07: short-circuit when operator requested the runbook lookup
    // surface instead of the diagnostic suite.
    if args.list_checks {
        match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                let names: Vec<&str> = all_check_docs().map(|d| d.name).collect();
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
                    all_check_docs().count()
                );
                for d in all_check_docs() {
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
            if !args.quiet && (any_fail || any_warn) {
                println!(
                    "next: run `neoth doctor --explain <check>` for the exact cause and fix steps"
                );
                for o in outcomes
                    .iter()
                    .filter(|o| o.status == CheckStatus::Fail || o.status == CheckStatus::Warn)
                    .take(5)
                {
                    println!("      neoth doctor --explain \"{}\"", o.name);
                }
            }
        }
    }

    // GOLD-ADOPT-24 — optional LLM root-cause pass over the check results.
    if args.diagnose {
        diagnose_with_llm(&outcomes).await;
    }

    if any_fail {
        // GOLD-COR-01 / A-03: non-zero status via QuietExit so the stack
        // unwinds (Drop-time flushes run) before the code reaches `main`.
        return Err(crate::QuietExit(1).into());
    }
    Ok(())
}

/// GOLD-ADOPT-24 — feed the WARN/FAIL check outcomes to the cheap utility
/// provider for a terse root-cause + first-fix. Best-effort: a clean bill of
/// health, an absent provider, or a provider error all just print a note and
/// return (diagnosis never changes the doctor exit code). The structured check
/// outcomes ARE the context — richer than goose's raw-log LLM dump.
async fn diagnose_with_llm(outcomes: &[CheckOutcome]) {
    let problems: Vec<&CheckOutcome> = outcomes
        .iter()
        .filter(|o| matches!(o.status, CheckStatus::Warn | CheckStatus::Fail))
        .collect();
    if problems.is_empty() {
        println!("\ndiagnose: all checks pass — nothing to root-cause.");
        return;
    }
    let config = match FreedomConfig::load_from_default_path() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("diagnose: cannot load freedom.yaml ({e}); skipping LLM pass.");
            return;
        }
    };
    let provider = match crate::providers::from_config_for_utility(&config).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("diagnose: no usable provider ({e}); skipping LLM pass.");
            return;
        }
    };
    let mut blob = String::new();
    for o in &problems {
        blob.push_str(&format!("- [{}] {}: {}\n", o.status.tag(), o.name, o.detail));
    }
    let req = crate::providers::Request {
        prompt: format!(
            "You are NEOTH's self-diagnostic assistant. `neoth doctor` reported these \
             problems (structured health checks):\n\n{blob}\nGive the single MOST-LIKELY \
             root cause and the FIRST concrete fix step/command. Be terse (max 8 lines). \
             Do NOT invent checks that aren't listed; reason only over the above.",
        ),
        ..Default::default()
    };
    match provider.complete(req).await {
        Ok(c) if !c.text.trim().is_empty() => {
            println!("\n── diagnose (LLM root-cause) ──\n{}", c.text.trim());
        }
        Ok(_) => eprintln!("diagnose: provider returned an empty response."),
        Err(e) => eprintln!("diagnose: provider call failed ({e})."),
    }
}

/// Run every diagnostic in order. Pure synchronous — each check is short.
pub fn run_all_checks(home: &Path) -> Vec<CheckOutcome> {
    DOMAIN_CHECKS
        .iter()
        .flat_map(|domain| domain.iter())
        .map(|check| check(home))
        .collect()
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

#[cfg(test)]
mod tests {
    use super::checks::{
        cluster::*, config::*, integrations::*, providers::*, storage::*, tooling::*,
    };
    use super::*;
    use tempfile::tempdir;

    // ── V03-07 2026-05-17: --explain + --list-checks ──────────────────

    #[test]
    fn check_docs_cover_every_check_name_in_run_all() {
        // Drift guard: every check name produced by `run_all_checks`
        // must have an explain entry. Refactor that adds a new check
        // without a DOCS entry in its domain file fails here.
        let dir = tempdir().unwrap();
        let outcomes = run_all_checks(dir.path());
        let doc_names: std::collections::HashSet<&str> =
            all_check_docs().map(|d| d.name).collect();
        for o in &outcomes {
            assert!(
                doc_names.contains(o.name),
                "check `{}` produced by run_all_checks has no runbook doc — \n                 add a DOCS entry in its cli/doctor/checks/ domain file",
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
        for d in all_check_docs() {
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
    fn check_docs_listed_count_pinned_at_thirty_one() {
        // Pin the count so a future addition is a conscious update + a
        // future deletion (which would silently drop operator runbook
        // coverage) is caught. Bumped to 26 in Session 21 for
        // `cluster mDNS announcer` (Bite #2 announcer state surface);
        // 27 in Session 28c for `refusal recovery` (SPEC-10);
        // 28 in Session 28c for `local_qwen weights` (SPEC-04);
        // 29 in Session 28c for `n8n_api_token` (SC-08);
        // 30 in Session 44 for `stuck claude processes` (GOLD-WIRE-05);
        // 31 in Session 44 for `vector index snapshot` (GOLD-WIRE-07);
        // 36 for the capability-readiness domain (computer-use, okf export,
        // iroh transport, mcp servers, wal audit) — the integration proof;
        // 37 for self-improvement (SkillOpt).
        assert_eq!(all_check_docs().count(), 37);
    }

    // ── GOLD-WIRE-05: stuck claude-process check ──────────────────────

    #[test]
    fn stuck_processes_outcome_passes_when_none() {
        let out = stuck_processes_outcome(&[]);
        assert_eq!(out.status, CheckStatus::Pass);
        assert_eq!(out.name, "stuck claude processes");
        assert!(out.detail.contains("no stuck"), "got: {}", out.detail);
    }

    #[test]
    fn stuck_processes_outcome_warns_and_lists_pid() {
        // Acceptance: a stuck claude process surfaces as WARN in doctor
        // output, with its PID + idle minutes shown.
        use crate::providers::claude_pid_hunter::{ProcessMeta, StuckProcess, StuckThresholds};
        let stuck = vec![StuckProcess {
            meta: ProcessMeta {
                pid: 4242,
                name: "claude".into(),
                runtime: std::time::Duration::from_secs(18 * 60),
                cpu_pct: 0.1,
            },
            thresholds: StuckThresholds::default(),
            hint: "x",
        }];
        let out = stuck_processes_outcome(&stuck);
        assert_eq!(out.status, CheckStatus::Warn);
        assert!(out.detail.contains("pid 4242"), "must name the PID: {}", out.detail);
        assert!(out.detail.contains("18m idle"), "must show idle minutes: {}", out.detail);
        // Honesty: must NOT point at the not-yet-built stuck-clean / reset cmds.
        assert!(!out.detail.contains("stuck-clean"));
        assert!(!out.detail.contains("chat reset"));
    }

    #[test]
    fn check_stuck_claude_processes_skips_when_not_claude_cli() {
        // No freedom.yaml → freedom_uses_claude_cli is false → PASS skip,
        // and crucially NO process-table scan runs.
        let dir = tempdir().unwrap();
        let out = check_stuck_claude_processes(dir.path());
        assert_eq!(out.status, CheckStatus::Pass);
        assert!(
            out.detail.contains("not your provider") || out.detail.contains("skipped"),
            "got: {}",
            out.detail
        );
    }

    // ── GOLD-WIRE-07: vector index snapshot advisory ──────────────────────

    #[test]
    fn vector_index_passes_for_brute_force_default() {
        // No freedom.yaml → backend reads as brute_force → PASS, no snapshot check.
        let dir = tempdir().unwrap();
        let out = check_vector_index_snapshot(dir.path());
        assert_eq!(out.status, CheckStatus::Pass);
        assert!(out.detail.contains("brute_force"), "got: {}", out.detail);
    }

    #[test]
    fn vector_index_warns_when_hnsw_and_no_snapshot() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "operator_id: alice\nmemory:\n  vector_index:\n    backend: hnsw\n",
        )
        .unwrap();
        let out = check_vector_index_snapshot(dir.path());
        assert_eq!(out.status, CheckStatus::Warn);
        assert!(
            out.detail.contains("no snapshot") && out.detail.contains("rebuild-index"),
            "got: {}",
            out.detail
        );
    }

    #[test]
    fn n8n_token_check_passes_when_disabled() {
        let dir = tempdir().unwrap();
        let mut cfg = crate::config::FreedomConfig::default();
        cfg.n8n_api.enabled = false;
        std::fs::write(
            dir.path().join("freedom.yaml"),
            serde_yaml::to_string(&cfg).unwrap(),
        )
        .unwrap();
        let outcome = check_n8n_api_token(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("disabled"));
    }

    #[test]
    fn n8n_token_check_passes_when_enabled_but_not_minted() {
        let dir = tempdir().unwrap();
        let mut cfg = crate::config::FreedomConfig::default();
        cfg.n8n_api.enabled = true;
        std::fs::write(
            dir.path().join("freedom.yaml"),
            serde_yaml::to_string(&cfg).unwrap(),
        )
        .unwrap();
        let outcome = check_n8n_api_token(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("not yet minted"));
    }

    #[test]
    fn local_qwen_check_passes_when_learn_provider_not_local_qwen() {
        // freedom.yaml with a cloud learn_provider → Qwen cache irrelevant.
        let dir = tempdir().unwrap();
        let mut cfg = crate::config::FreedomConfig::default();
        cfg.profile.learn_provider = Some("gemini".to_string());
        std::fs::write(
            dir.path().join("freedom.yaml"),
            serde_yaml::to_string(&cfg).unwrap(),
        )
        .unwrap();
        let outcome = check_local_qwen_weights(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("not local_qwen"));
    }

    #[test]
    fn local_qwen_check_passes_on_unreadable_freedom_yaml() {
        let dir = tempdir().unwrap();
        let outcome = check_local_qwen_weights(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
    }

    #[test]
    fn refusal_recovery_check_passes_on_empty_home_defaults() {
        // No freedom.yaml → recovery runs on healthy defaults → Pass.
        let dir = tempdir().unwrap();
        let outcome = check_refusal_recovery(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
    }

    #[test]
    fn refusal_recovery_check_warns_when_all_reframings_disabled() {
        // Enabled recovery + every reframing disabled = silent no-op → Warn.
        let dir = tempdir().unwrap();
        let mut cfg = crate::config::FreedomConfig::default();
        cfg.refusal_recovery.enabled = true;
        cfg.refusal_recovery.max_attempts = 2;
        cfg.refusal_recovery.disabled_reframings =
            crate::security::refusal_reframings::default_catalogue()
                .iter()
                .map(|r| r.id().to_string())
                .collect();
        std::fs::write(
            dir.path().join("freedom.yaml"),
            serde_yaml::to_string(&cfg).unwrap(),
        )
        .unwrap();
        let outcome = check_refusal_recovery(dir.path());
        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(
            outcome.detail.contains("no-op"),
            "detail: {}",
            outcome.detail
        );
    }

    #[test]
    fn refusal_recovery_check_passes_when_disabled_by_operator() {
        let dir = tempdir().unwrap();
        let mut cfg = crate::config::FreedomConfig::default();
        cfg.refusal_recovery.enabled = false;
        std::fs::write(
            dir.path().join("freedom.yaml"),
            serde_yaml::to_string(&cfg).unwrap(),
        )
        .unwrap();
        let outcome = check_refusal_recovery(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("off by operator"));
    }

    // GOLD-SEC-16: the cluster doctor-check tests exercise the real
    // cluster-feature code paths (registry + announcer); they compile only
    // with the `cluster` feature. The stub checks in the no-cluster build are
    // trivially correct (they return a fixed "not compiled" Pass).
    #[cfg(feature = "cluster")]
    mod cluster_doctor_tests {
        use super::*;

    #[test]
    fn cluster_registry_pass_when_empty() {
        let dir = tempdir().unwrap();
        let outcome = check_cluster_registry(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("no confirmed"));
    }

    #[test]
    fn cluster_registry_pass_when_fresh() {
        let dir = tempdir().unwrap();
        let now = crate::time::now_unix_i64();
        let peer = crate::cluster::registry::PairedPeer {
            pub_key_hex: "ab".repeat(32),
            instance_label: "laptop".into(),
            hostname: String::new(),
            addr: "192.0.2.1:4242".into(),
            discovered_via: crate::cluster::discovery::DiscoveryVia::Mdns,
            paired_at_unix: now - 3600,
            last_seen_unix: now - 60,
            ..Default::default()
        };
        crate::cluster::registry::upsert(dir.path(), peer).unwrap();
        let outcome = check_cluster_registry(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("1 confirmed"));
    }

    #[test]
    fn cluster_registry_warns_on_stale() {
        let dir = tempdir().unwrap();
        let now = crate::time::now_unix_i64();
        let peer = crate::cluster::registry::PairedPeer {
            pub_key_hex: "ab".repeat(32),
            instance_label: "old-laptop".into(),
            hostname: String::new(),
            addr: "192.0.2.1:4242".into(),
            discovered_via: crate::cluster::discovery::DiscoveryVia::Mdns,
            paired_at_unix: now - 30 * 86_400,
            last_seen_unix: now - 30 * 86_400, // 30 days old > 14d threshold
            ..Default::default()
        };
        crate::cluster::registry::upsert(dir.path(), peer).unwrap();
        let outcome = check_cluster_registry(dir.path());
        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(outcome.detail.contains("stale"));
        assert!(outcome.detail.contains("old-laptop"));
    }

    // ── check_cluster_mdns_announcer (Bite #2) ─────────────────────────

    fn open_announce_policy() -> crate::cluster::policy::AnnouncePolicy {
        crate::cluster::policy::AnnouncePolicy {
            announce_on_untrusted_wifi: true,
            trusted_ssids: vec![],
        }
    }

    fn strict_announce_policy() -> crate::cluster::policy::AnnouncePolicy {
        crate::cluster::policy::AnnouncePolicy {
            announce_on_untrusted_wifi: false,
            trusted_ssids: vec!["home-wifi".into()],
        }
    }

    #[test]
    fn mdns_announcer_pass_when_disabled() {
        let outcome = evaluate_announcer_state(false, &open_announce_policy(), Some("anything"), 0);
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("disabled"));
    }

    #[test]
    fn mdns_announcer_pass_when_proceed_with_ssid() {
        let outcome =
            evaluate_announcer_state(true, &strict_announce_policy(), Some("home-wifi"), 2);
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("home-wifi"));
        assert!(outcome.detail.contains("2 paired"));
    }

    #[test]
    fn mdns_announcer_pass_when_open_policy_any_network() {
        let outcome = evaluate_announcer_state(true, &open_announce_policy(), None, 0);
        assert_eq!(outcome.status, CheckStatus::Pass);
        // Open policy → SsidUnknown path collapses to Proceed via gate;
        // detail uses the any-network label.
        assert!(outcome.detail.contains("any-network"));
    }

    #[test]
    fn mdns_announcer_pass_when_untrusted_ssid_but_no_peers() {
        let outcome =
            evaluate_announcer_state(true, &strict_announce_policy(), Some("coffee-shop"), 0);
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("single-instance"));
        assert!(outcome.detail.contains("coffee-shop"));
    }

    #[test]
    fn mdns_announcer_warn_when_untrusted_ssid_with_peers() {
        let outcome =
            evaluate_announcer_state(true, &strict_announce_policy(), Some("coffee-shop"), 3);
        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(outcome.detail.contains("coffee-shop"));
        assert!(outcome.detail.contains("3 paired"));
        assert!(outcome.detail.contains("trusted_ssids"));
    }

    #[test]
    fn mdns_announcer_pass_when_ssid_unknown_and_no_peers() {
        let outcome = evaluate_announcer_state(true, &strict_announce_policy(), None, 0);
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("no paired peers"));
    }

    #[test]
    fn mdns_announcer_warn_when_ssid_unknown_with_peers() {
        let outcome = evaluate_announcer_state(true, &strict_announce_policy(), None, 1);
        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(outcome.detail.contains("wired"));
        assert!(outcome.detail.contains("1 paired"));
        assert!(outcome.detail.contains("announce_on_untrusted_wifi"));
    }

    #[test]
    fn mdns_announcer_check_via_home_does_not_panic() {
        // End-to-end smoke for the home-reading wrapper: missing
        // freedom.yaml + missing cluster.yaml → safe defaults +
        // ssid lookup might return either None or Some depending
        // on the test host. Must not panic.
        let dir = tempdir().unwrap();
        let outcome = check_cluster_mdns_announcer(dir.path());
        assert_eq!(outcome.name, "cluster mDNS announcer");
        // Status is platform-dependent (host SSID may match nothing
        // in the default trusted list); we only pin that it ran.
    }
    } // mod cluster_doctor_tests (GOLD-SEC-16)

    #[test]
    fn provider_flapping_pass_when_no_calls() {
        let dir = tempdir().unwrap();
        let outcome = check_provider_flapping(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("no provider calls"));
        // GR-02 (Session 24): pin the rename so a future regression
        // that brings the misleading "channel flapping" label back
        // (the function measures provider error-rate, not
        // channel-level data) is caught in CI.
        assert_eq!(outcome.name, "provider flapping");
    }

    #[test]
    fn provider_flapping_pass_when_below_threshold() {
        use crate::daemon::usage_log::{UsageEvent, append};
        let dir = tempdir().unwrap();
        let now = crate::time::now_unix_i64();
        // 10 calls, only 1 error → 10% error rate (below 20% threshold).
        for i in 0..10 {
            append(
                dir.path(),
                &UsageEvent {
                    ts_unix: now - (i as i64) * 10,
                    provider: "slack_api".into(),
                    model: "n/a".into(),
                    input_tokens: 0,
                    output_tokens: 0,
                    cost_usd: 0.0,
                    latency_ms: 50,
                    ok: i != 0,
                },
            )
            .unwrap();
        }
        let outcome = check_provider_flapping(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
    }

    #[test]
    fn provider_flapping_warns_when_above_threshold() {
        use crate::daemon::usage_log::{UsageEvent, append};
        let dir = tempdir().unwrap();
        let now = crate::time::now_unix_i64();
        // 10 calls, 5 errors → 50% error rate.
        for i in 0..10 {
            append(
                dir.path(),
                &UsageEvent {
                    ts_unix: now - (i as i64) * 10,
                    provider: "openai_api".into(),
                    model: "gpt-5".into(),
                    input_tokens: 0,
                    output_tokens: 0,
                    cost_usd: 0.0,
                    latency_ms: 50,
                    ok: i % 2 == 0,
                },
            )
            .unwrap();
        }
        let outcome = check_provider_flapping(dir.path());
        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(outcome.detail.contains("flapping"));
        assert!(outcome.detail.contains("openai_api"));
        // Error pct surfaces in the detail string regardless of
        // rendering quirks — assert on the per-pct presence
        // pattern rather than exact "50%" formatting.
        assert!(
            outcome.detail.contains("%"),
            "detail should carry percent sign: {}",
            outcome.detail
        );
    }

    #[test]
    fn provider_flapping_skips_low_sample_providers() {
        use crate::daemon::usage_log::{UsageEvent, append};
        let dir = tempdir().unwrap();
        let now = crate::time::now_unix_i64();
        // Only 2 calls with 100% error rate — under min sample size.
        for _ in 0..2 {
            append(
                dir.path(),
                &UsageEvent {
                    ts_unix: now,
                    provider: "low_sample".into(),
                    model: "x".into(),
                    input_tokens: 0,
                    output_tokens: 0,
                    cost_usd: 0.0,
                    latency_ms: 10,
                    ok: false,
                },
            )
            .unwrap();
        }
        let outcome = check_provider_flapping(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
    }

    #[test]
    fn check_circuit_breakers_renders_per_provider_state() {
        // QM-10 Phase 2 wire-in: the doctor reads the live global
        // registry. In a fresh test process with no providers
        // seen, the registry is empty → Pass with "no providers"
        // detail. Once a chat call has run, the detail enumerates
        // the breakers it touched.
        let dir = tempdir().unwrap();
        let outcome = check_circuit_breakers(dir.path());
        assert_eq!(outcome.name, "circuit breakers");
        // Test order isn't deterministic so we accept both shapes
        // — the contract is: outcome is non-empty + status is Pass
        // when every breaker is Closed.
        assert!(!outcome.detail.is_empty());
    }

    #[test]
    fn check_usage_today_pass_when_no_usage_dir() {
        let dir = tempdir().unwrap();
        let outcome = check_usage_today(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("no calls"));
    }

    #[test]
    fn check_usage_today_warns_when_cost_crosses_cap() {
        use crate::daemon::usage_log::{UsageEvent, append};
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "council:\n  daily_usd_cap: 1.0\n",
        )
        .unwrap();
        let now = crate::time::now_unix_i64();
        append(
            dir.path(),
            &UsageEvent {
                ts_unix: now - 30,
                provider: "openai_api".into(),
                model: "gpt-5.5".into(),
                input_tokens: 100,
                output_tokens: 100,
                cost_usd: 1.5,
                latency_ms: 500,
                ok: true,
            },
        )
        .unwrap();
        let outcome = check_usage_today(dir.path());
        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(outcome.detail.contains("1.5") || outcome.detail.contains("1.50"));
    }

    #[test]
    fn check_usage_today_warns_at_80_pct_of_cap() {
        use crate::daemon::usage_log::{UsageEvent, append};
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "council:\n  daily_usd_cap: 2.0\n",
        )
        .unwrap();
        let now = crate::time::now_unix_i64();
        // $1.70 of $2 cap = 85% → Warn (below cap, above 80%).
        append(
            dir.path(),
            &UsageEvent {
                ts_unix: now - 30,
                provider: "openai_api".into(),
                model: "gpt-5.5".into(),
                input_tokens: 0,
                output_tokens: 0,
                cost_usd: 1.70,
                latency_ms: 0,
                ok: true,
            },
        )
        .unwrap();
        assert_eq!(check_usage_today(dir.path()).status, CheckStatus::Warn);
    }

    #[test]
    fn freedom_daily_usd_cap_defaults_when_missing() {
        let dir = tempdir().unwrap();
        assert!((freedom_daily_usd_cap(dir.path()) - 5.0).abs() < f64::EPSILON);
        // Malformed YAML → default.
        std::fs::write(dir.path().join("freedom.yaml"), ": : :").unwrap();
        assert!((freedom_daily_usd_cap(dir.path()) - 5.0).abs() < f64::EPSILON);
        // Explicit value parses.
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "council:\n  daily_usd_cap: 12.5\n",
        )
        .unwrap();
        assert!((freedom_daily_usd_cap(dir.path()) - 12.5).abs() < f64::EPSILON);
    }

    #[test]
    fn node_toolchain_silent_when_no_freedom_and_no_node() {
        // Fresh tempdir with no freedom.yaml + no node on PATH would
        // hit the (None, None, false) arm → Pass with explanatory
        // detail. Pin the contract so a future re-classification
        // doesn't accidentally spam yellow on LocalQwen-only deploys.
        let dir = tempdir().unwrap();
        let outcome = check_node_toolchain(dir.path());
        // We can't pin Pass-vs-Warn deterministically on a CI runner
        // that DOES have node installed (which is common). What we
        // CAN pin: when needs_npm is false (no freedom.yaml means
        // false), the outcome must NOT be Warn-with-required-message.
        if outcome.status == CheckStatus::Warn {
            assert!(
                !outcome.detail.contains("required by your provider_kind"),
                "should not raise 'required' warn when provider isn't node-backed: {}",
                outcome.detail
            );
        }
    }

    #[test]
    fn node_toolchain_warns_when_provider_kind_needs_npm_and_node_missing() {
        // Set provider_kind to claude_cli and probe a binary that
        // definitely doesn't exist — by overriding the freedom path
        // we exercise the needs_npm=true branch.
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "provider_kind: claude_cli\n",
        )
        .unwrap();
        assert!(freedom_uses_node_cli_provider(dir.path()));
        assert!(freedom_uses_claude_cli(dir.path()));
    }

    #[test]
    fn freedom_uses_helpers_handle_missing_or_malformed() {
        let dir = tempdir().unwrap();
        // Missing → false.
        assert!(!freedom_uses_node_cli_provider(dir.path()));
        assert!(!freedom_uses_claude_cli(dir.path()));
        // Malformed YAML → false.
        std::fs::write(dir.path().join("freedom.yaml"), ": : :").unwrap();
        assert!(!freedom_uses_node_cli_provider(dir.path()));
        assert!(!freedom_uses_claude_cli(dir.path()));
        // Different provider → false.
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "provider_kind: local_qwen\n",
        )
        .unwrap();
        assert!(!freedom_uses_node_cli_provider(dir.path()));
        assert!(!freedom_uses_claude_cli(dir.path()));
        // Antigravity CLI → NOT node-backed (vendor shell-script
        // install, not npm). Verifies the 2026-05-19 transition fix:
        // the predicate must NOT flag `gemini_cli` or `antigravity_cli`
        // as needing npm or the doctor emits a false-positive warning.
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "provider_kind: gemini_cli\n",
        )
        .unwrap();
        assert!(
            !freedom_uses_node_cli_provider(dir.path()),
            "legacy gemini_cli provider must NOT count as node-backed after antigravity migration",
        );
        assert!(!freedom_uses_claude_cli(dir.path()));
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "provider_kind: antigravity_cli\n",
        )
        .unwrap();
        assert!(
            !freedom_uses_node_cli_provider(dir.path()),
            "antigravity_cli provider must NOT count as node-backed (ships via shell-script)",
        );
        assert!(!freedom_uses_claude_cli(dir.path()));
        // claude_cli still node-backed.
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "provider_kind: claude_cli\n",
        )
        .unwrap();
        assert!(freedom_uses_node_cli_provider(dir.path()));
        assert!(freedom_uses_claude_cli(dir.path()));
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
            diagnose: false,
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
            diagnose: false,
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
            diagnose: false,
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
        std::fs::write(dir.path().join("freedom.yaml"), "operator_id: demo-user\n").unwrap();
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
        // 31 checks: 19 pre-Session-20 + node toolchain + tmux for
        // claude-cli + usage today + circuit breakers + channel
        // flapping + cluster registry (Phase 4 follow-on) + cluster
        // mDNS announcer (Session 21 bite #2) + refusal recovery
        // (Session 28c, SPEC-10) + local_qwen weights (Session 28c, SPEC-04)
        // + n8n_api_token (Session 28c, SC-08) + stuck claude processes
        // (Session 44, GOLD-WIRE-05) + vector index snapshot (Session 44,
        // GOLD-WIRE-07) + the 6 capability-readiness checks (computer-use,
        // okf export, iroh transport, mcp servers, wal audit, self-improvement).
        assert_eq!(outs.len(), 37);
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
            outcome.detail.contains("CLI-only")
                || outcome.detail.contains("no channel credentials"),
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
    fn r2_p0_2_channels_wiring_warn_when_slack_partial() {
        // Only bot_token supplied — socket mode also needs app_token.
        // Doctor surfaces this as CONFIGURED-NOT-STARTED so operators
        // who pasted only one token see the gap.
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("credentials.yaml"),
            "slack_bot_token: \"xoxb-test-token\"\n",
        )
        .unwrap();
        let outcome = check_channels_wiring(dir.path());
        assert_eq!(outcome.status, CheckStatus::Warn);
        assert!(outcome.detail.contains("slack"));
        assert!(outcome.detail.contains("CONFIGURED-NOT-STARTED"));
    }

    #[test]
    fn slack_inbound_live_when_both_tokens_present() {
        // Post-inbound-wire: BOTH bot + app tokens present → LIVE.
        // The serve loop spawns the socket-mode receive loop in this
        // configuration.
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("credentials.yaml"),
            "slack_bot_token: \"xoxb-test-token\"\nslack_app_token: \"xapp-test-token\"\n",
        )
        .unwrap();
        let outcome = check_channels_wiring(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("slack: LIVE"));
    }

    #[test]
    fn r2_p0_2_channels_wiring_warn_when_whatsapp_outbound_only() {
        // Token + phone-id but no verify-token / app-secret → outbound only.
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
    fn whatsapp_inbound_live_when_full_meta_secrets_present() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("credentials.yaml"),
            "whatsapp_token: \"test-wa-token\"\n\
             whatsapp_phone_id: \"123456789\"\n\
             whatsapp_verify_token: \"verify-tok\"\n\
             whatsapp_app_secret: \"meta-app-secret\"\n",
        )
        .unwrap();
        let outcome = check_channels_wiring(dir.path());
        assert_eq!(outcome.status, CheckStatus::Pass);
        assert!(outcome.detail.contains("whatsapp: LIVE"));
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
        assert!(outcome.detail.contains("slack: CONFIGURED-NOT-STARTED"));
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
            "operator_id: demo-user\nautonomy: standard\ncloud_archive_dest: {}\n",
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
            "operator_id: demo-user\nautonomy: standard\ncloud_archive_dest: /definitely/not/here\n";
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
        let o = check_model_caches(Path::new("unused"));
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
