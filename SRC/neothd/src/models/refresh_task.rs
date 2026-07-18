//! Daemon-internal periodic catalog-refresh task.
//!
//! NEOTH's `cron` module (Phase 11b) drives operator-defined
//! prompt-based jobs — that's not the right surface for an internal
//! daemon task like "rebuild the models catalog once per day". This
//! module ships the daemon-internal cron-like loop instead.
//!
//! Lifecycle: spawned from [`crate::cli::serve::run_serve`] on
//! daemon startup. Sleeps until the configured interval elapses,
//! then runs [`crate::models::discovery::discover_all`], then loops.
//!
//! Honours the operator's autonomy level + the catalog TTL — when
//! the existing catalog is still fresh, the task ticks but does
//! nothing.
//!
//! Failure handling: a single source's failure is recorded inside
//! the catalog itself (`ProviderCatalog::last_error`); a wholesale
//! failure of the discovery run is logged via `tracing::warn` and
//! the task continues on its next tick. Never panics — the daemon
//! must not crash because one model provider's REST endpoint is
//! down.

use std::path::PathBuf;
use std::time::Duration;

use crate::config::FreedomConfig;
#[cfg(test)]
use crate::models::catalog::DEFAULT_TTL_SECS;
use crate::models::catalog::{ModelsCatalog, now_unix};
use crate::models::discovery;

/// Minimum delay between two refresh attempts. Picked to be
/// well below the default TTL (24h) so that a daemon that's been up
/// for ~25 hours catches the stale window quickly, while keeping the
/// sleep granularity low enough that operator-tweaked TTL overrides
/// land within an hour.
pub const REFRESH_TICK_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Spawned at daemon startup. Runs forever until the runtime is
/// dropped. The returned `JoinHandle` can be awaited on shutdown if
/// the caller wants to wait for an in-flight discovery pass to
/// complete; in practice the daemon's graceful-shutdown drops the
/// handle and lets tokio cancel the task.
pub fn spawn_periodic_refresh(home: PathBuf, config: FreedomConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_refresh_loop(home, config, REFRESH_TICK_INTERVAL).await;
    })
}

/// Loop body — extracted from the spawn wrapper so tests can drive it
/// with a short tick interval + abort via a kill switch.
pub async fn run_refresh_loop(home: PathBuf, config: FreedomConfig, tick: Duration) {
    let catalog_path = ModelsCatalog::default_path(&home);
    let mut interval = tokio::time::interval(tick);
    // The first tick fires immediately — that's intentional. Operators
    // who just installed NEOTH and ran `neoth serve` see a populated
    // catalog within seconds, not hours.
    loop {
        interval.tick().await;
        if let Err(e) = run_one_pass(&catalog_path, &config).await {
            tracing::warn!(
                error = %e,
                "models catalog refresh task: full-run failure (will retry next tick)"
            );
        }
    }
}

/// One refresh attempt. Skips when the catalog is fresh for every
/// provider; otherwise runs `discover_all` and persists results.
async fn run_one_pass(
    catalog_path: &std::path::Path,
    config: &FreedomConfig,
) -> anyhow::Result<()> {
    let existing = ModelsCatalog::load_snapshot_strict_from(catalog_path)?
        .map(|snapshot| snapshot.catalog)
        .unwrap_or_default();
    let now = now_unix();

    // Build the set of providers the operator has configured + see
    // which ones are already fresh in the catalog. When every
    // configured source is fresh, skip the network round-trip.
    let home = catalog_path.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "model catalog path `{}` has no NEOTH instance directory",
            catalog_path.display()
        )
    })?;
    let plan = discovery::build_sources_from_config_at(config, home)?;
    if plan.is_empty() {
        tracing::debug!("models catalog refresh task: no providers configured — nothing to do");
        return Ok(());
    }
    let report =
        discovery::discover_with_plan(catalog_path, plan.stale_only(&existing, now)).await?;
    if report.fresh.len() == report.configured.len() {
        tracing::debug!(
            providers = report.configured.len(),
            "models catalog refresh task: every configured provider already fresh"
        );
        return Ok(());
    }
    tracing::info!(
        fresh = report.fresh.len(),
        refreshed = report.refreshed.len(),
        failed = report.failed.len(),
        skipped_no_creds = report.skipped_no_creds.len(),
        credential_failures = report.credential_failures.len(),
        configuration_failures = report.configuration_failures.len(),
        unsupported = report.unsupported.len(),
        blocked_no_consent = report.blocked_no_consent.len(),
        "models catalog refresh task: discovery pass complete"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::catalog::{ModelEntry, ProviderCatalog, SourceOrigin};
    use tempfile::tempdir;

    #[test]
    fn refresh_tick_interval_is_well_below_default_ttl() {
        // The tick must sample the TTL window at least 12× per day or
        // the operator's freshness expectations are off-by-half.
        let day = Duration::from_secs(DEFAULT_TTL_SECS);
        let ratio = day.as_secs() / REFRESH_TICK_INTERVAL.as_secs();
        assert!(
            ratio >= 12,
            "tick interval should sample the TTL window at least 12× per day (got {ratio}×)"
        );
    }

    #[tokio::test]
    async fn one_pass_skips_when_every_provider_fresh() {
        let dir = tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let neoth_dir = home.join(".neoth");
        std::fs::create_dir_all(&neoth_dir).unwrap();
        let catalog_path = ModelsCatalog::default_path(&home);

        // Operator config — uses ClaudeCli (drives the anthropic source).
        let mut config = FreedomConfig {
            provider_kind: Some(crate::cli::init::ProviderKind::ClaudeCli),
            provider_key: Some(crate::secret::SecretString::new("sk-ant-test".into())),
            ..Default::default()
        };
        config.profile.learn_provider = None;
        crate::consent::grant(&home, crate::cli::init::ProviderKind::ClaudeCli).unwrap();
        let plan = discovery::build_sources_from_config_at(&config, &home).unwrap();
        let binding_hash = plan
            .binding_hash_for_test(discovery::ANTHROPIC_CATALOG_PROVIDER)
            .expect("configured Claude CLI source")
            .to_string();

        // Seed a fresh catalog for one provider that the config also references.
        let mut cat = ModelsCatalog::default().with_path(catalog_path.clone());
        let mut pc = ProviderCatalog::default();
        pc.fetched_at_unix = now_unix();
        pc.binding_hash = Some(binding_hash);
        pc.source = SourceOrigin::Api;
        pc.models = vec![ModelEntry::new("claude-opus-4-7")];
        cat.providers.insert("anthropic_api".to_string(), pc);
        cat.save().unwrap();

        // One pass should NOT touch the network. There's no way to
        // assert that directly, but the function returning `Ok(())`
        // without hanging on a real HTTP call (which would have
        // timed out at 30s) is the proof.
        run_one_pass(&catalog_path, &config).await.unwrap();
    }

    #[tokio::test]
    async fn one_pass_no_op_for_empty_config() {
        let dir = tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let catalog_path = ModelsCatalog::default_path(&home);
        let config = FreedomConfig::default();
        run_one_pass(&catalog_path, &config).await.unwrap();
        // Catalog file must NOT have been written.
        assert!(!catalog_path.exists());
    }
}
