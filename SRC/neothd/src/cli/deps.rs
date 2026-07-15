//! `neoth deps-scan <manifest>` — run the dependency-health gates over a
//! `package.json` and report findings (GOLD-ADAPT-SNYK-03 wiring).
//!
//! The scanner ([`crate::security::dep_health::scan_manifest`] — OSV advisories,
//! typosquat heuristic, npm registry health) was built but had no CLI consumer
//! (the `// neoth:` note in `dep_health.rs` flagged the gap). This is that
//! consumer: an operator can vet a manifest before installing from it.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

#[derive(Args, Debug)]
pub struct DepsScanArgs {
    /// Path to a `package.json` manifest to scan.
    pub manifest: PathBuf,
    /// Emit the findings as JSON instead of the human table.
    #[arg(long)]
    pub json: bool,
}

pub async fn run_deps_scan(args: DepsScanArgs) -> Result<()> {
    let findings =
        crate::security::dep_health::scan_manifest(&args.manifest, crate::time::now_unix_i64())
            .await;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
        return Ok(());
    }

    if findings.is_empty() {
        println!(
            "deps-scan: {} — no dependency-health issues found",
            args.manifest.display()
        );
        return Ok(());
    }

    println!(
        "=== dependency health: {} ({} finding{}) ===",
        args.manifest.display(),
        findings.len(),
        if findings.len() == 1 { "" } else { "s" }
    );
    for f in &findings {
        println!("  {:<32} {:?}", f.package, f.kind);
    }
    Ok(())
}
