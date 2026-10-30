//! Explicit read-only acquisition inspection; legacy usage JSONL is not involved.
mod collector;
pub(super) mod provenance;

use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::Serialize;

use super::usage::{UsageArgs, UsageFormat};
use crate::wal::scan::{AuthenticatedPrefixScan, HomeWalFrameLocation};
use collector::{Collector, Limits, Location, Report};

const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Serialize)]
struct Inspection {
    schema: &'static str,
    scope: &'static str,
    association_scope: &'static str,
    association_semantics: &'static str,
    time_filter: &'static str,
    scope_absence: &'static str,
    full_history_complete: bool,
    atomic_latest_snapshot: bool,
    no_retained_segments: bool,
    scan: AuthenticatedPrefixScan,
    observations: Report,
}

fn location(source: &HomeWalFrameLocation) -> Location {
    Location {
        segment_name: source.segment_name.to_string_lossy().into_owned(),
        segment_generation: source.segment_generation,
        segment_seq: source.segment_seq,
        segment_start_ts_ns: source.segment_start_ts_ns,
        segment_node_id: source.segment_node_id,
        logical_offset: source.logical_offset,
    }
}

fn collect_after_scan<F>(since: u64, until: u64, scan: F) -> Result<Inspection>
where
    F: FnOnce(&mut Collector) -> Result<AuthenticatedPrefixScan>,
{
    if since > until {
        bail!("acquisition start must not be after end");
    }
    let mut collector = Collector::new(Limits {
        max_records: 20_000,
        max_diagnostics: 1_000,
        max_input_bytes: 8 * 1024 * 1024,
    });
    // Never finish or return buffered records after any scan/callback failure.
    let scan = scan(&mut collector)?;
    let observations = collector.finish(since, until)?;
    Ok(Inspection {
        schema: "neoth.provider-acquisition-inspection.v1",
        scope: "retained_authenticated_wal_prefix",
        association_scope: "metadata_correlation_within_scanned_home_not_causal_identity",
        association_semantics: "conflict_means_recorded_fields_differ_not_separate_events_double_debit_or_budget_discrepancy",
        time_filter: "recorded_request_or_acquisition_timestamp_inclusive_with_labeled_context",
        scope_absence: "null_is_not_represented_by_this_observation_not_complete_history",
        full_history_complete: false,
        atomic_latest_snapshot: false,
        no_retained_segments: scan.boundaries.is_empty(),
        scan,
        observations,
    })
}

fn inspect(home: &Path, since: u64, until: u64) -> Result<Inspection> {
    collect_after_scan(since, until, |collector| {
        crate::wal::scan::for_each_authenticated_prefix_frame_at_home(
            home,
            crate::wal::scan::supported_home_scan_limits(),
            |source, frame| {
                if frame.header.event_type == crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST {
                    collector.ingest_request(location(source), frame.payload)?;
                } else if frame.header.event_type == crate::wal::events::EVENT_TYPE_EXTENDED
                    && frame.header.event_subtype
                        == crate::wal::events::ExtendedSubtype::ProviderBudgetAcquired as u8
                {
                    collector.ingest_acquisition(location(source), frame.payload)?;
                }
                Ok(())
            },
        )
    })
}

/// Enforce the output cap during serialization, before allocating a larger buffer.
struct BoundedOutput {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self.bytes.len().checked_add(bytes.len()) {
            Some(total) if total <= self.limit => {
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            _ => Err(io::Error::other("acquisition output limit exceeded")),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn render(inspection: &Inspection, format: UsageFormat) -> Result<String> {
    let mut output = BoundedOutput {
        bytes: Vec::new(),
        limit: MAX_OUTPUT_BYTES,
    };
    match format {
        UsageFormat::Json => serde_json::to_writer_pretty(&mut output, inspection)?,
        UsageFormat::Table => {
            writeln!(
                output,
                "Acquisition observations [{} .. {}] (inclusive recorded timestamps)",
                inspection.observations.since_unix, inspection.observations.until_unix
            )?;
            writeln!(
                output,
                "Retained segments={} authenticated_bytes_complete={} decoding_complete={}",
                inspection.scan.boundaries.len(),
                inspection.scan.complete,
                inspection.observations.semantic_decode_complete
            )?;
            writeln!(
                output,
                "This is a retained snapshot, not complete history or an atomic latest view."
            )?;
            writeln!(
                output,
                "Matches compare recorded metadata within this home; they do not prove causal identity."
            )?;
            writeln!(
                output,
                "Conflicts name differing recorded fields; they do not establish separate events, double debits or budget discrepancies."
            )?;
            writeln!(
                output,
                "Amounts are reservations, not spending, settlement or current balance."
            )?;
            writeln!(
                output,
                "None means no scope recorded in that observation; missing records remain unknown."
            )?;
            if inspection.no_retained_segments {
                writeln!(
                    output,
                    "No retained WAL segments; this does not establish zero usage."
                )?;
            }
            for boundary in &inspection.scan.boundaries {
                writeln!(
                    output,
                    "  segment {:?}: authenticated through {} of {} logical bytes",
                    boundary.segment_name, boundary.authenticated_through, boundary.logical_len
                )?;
            }
            for group in &inspection.observations.groups {
                writeln!(
                    output,
                    "\nInvocation {:?}: observed {:?}; differing fields: {:?}",
                    group.invocation_id, group.association, group.difference_fields
                )?;
                for request in &group.requests {
                    writeln!(
                        output,
                        "  request t={} in_window={} provider={:?} model={:?} binding={:?} at {:?}:{}",
                        request.record.ts_unix,
                        request.is_in_window,
                        request.record.provider,
                        request.record.wire_model,
                        request.record.request_binding_sha256,
                        request.location.segment_name,
                        request.location.logical_offset
                    )?;
                }
                for acquisition in &group.acquisitions {
                    writeln!(
                        output,
                        "  acquisition t={} in_window={} provider={:?} model={:?} binding={:?} at {:?}:{}",
                        acquisition.record.ts_unix,
                        acquisition.is_in_window,
                        acquisition.record.provider,
                        acquisition.record.wire_model,
                        acquisition.record.request_binding_sha256,
                        acquisition.location.segment_name,
                        acquisition.location.logical_offset
                    )?;
                    writeln!(
                        output,
                        "    daily_usd_nanos={:?} operation_tokens={:?} operation_microusd={:?} cluster_usd_nanos={:?} cluster_grant={:?}",
                        acquisition.record.daily_reserved_usd_nanos,
                        acquisition
                            .record
                            .operation
                            .as_ref()
                            .map(|value| value.reserved_tokens),
                        acquisition
                            .record
                            .operation
                            .as_ref()
                            .map(|value| value.reserved_microusd),
                        acquisition
                            .record
                            .cluster
                            .as_ref()
                            .map(|value| value.reserved_usd_nanos),
                        acquisition
                            .record
                            .cluster
                            .as_ref()
                            .map(|value| value.grant_id.as_str())
                    )?;
                }
            }
            for diagnostic in &inspection.observations.diagnostics {
                writeln!(
                    output,
                    "  scan-wide diagnostic: {} {} at {:?}:{}",
                    diagnostic.record_kind,
                    diagnostic.code,
                    diagnostic.location.segment_name,
                    diagnostic.location.logical_offset
                )?;
            }
        }
    }
    output.write_all(b"\n")?;
    String::from_utf8(output.bytes).context("encode acquisition inspection")
}

fn window<F>(args: &UsageArgs, now: F) -> Result<(u64, u64)>
where
    F: FnOnce() -> Result<i64>,
{
    let until = match args.until_unix {
        Some(until) => until,
        None => now()?,
    };
    let since = match args.since_unix {
        Some(since) => since,
        None => until
            .checked_sub(i64::from(args.days.max(1)) * 86_400)
            .context("acquisition time range underflow")?,
    };
    let since =
        u64::try_from(since).context("acquisition start must be a nonnegative timestamp")?;
    let until = u64::try_from(until).context("acquisition end must be a nonnegative timestamp")?;
    if since > until {
        bail!("acquisition start must not be after end");
    }
    Ok((since, until))
}

pub(super) fn run(home: &Path, args: UsageArgs) -> Result<()> {
    if args.currency.is_some() {
        bail!(
            "--currency cannot be used with --acquisitions; recorded units remain USD nanos and micro-USD"
        );
    }
    let format =
        UsageFormat::parse(&args.format).context("acquisition format must be table or json")?;
    let (since, until) = window(&args, || {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock before unix epoch")?
            .as_secs();
        i64::try_from(seconds).context("system clock exceeds timestamp range")
    })?;
    let inspection = inspect(home, since, until)?;
    let text = render(&inspection, format)?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(text.as_bytes())?;
    stdout.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::time::Duration;

    use clap::Parser;
    use serde_json::{Value, json};

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: UsageArgs,
    }

    fn request() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schema": "neoth.provider-lifecycle.v1",
            "invocation_id": "b".repeat(64), "request_binding_sha256": "a".repeat(64),
            "provider": "openai_api", "wire_model": "gpt-4o", "ts_unix": 10,
            "private_fixture_extra": "never-include-this-content",
        }))
        .unwrap()
    }

    fn acquisition() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schema": "neoth.provider-budget-acquired.v1",
            "invocation_id": "b".repeat(64), "request_binding_sha256": "a".repeat(64),
            "provider": "openai_api", "wire_model": "gpt-4o", "ts_unix": 11,
            "daily_reserved_usd_nanos": 0,
            "operation": {"reserved_tokens": 128, "reserved_microusd": 25},
            "cluster": null,
        }))
        .unwrap()
    }

    async fn real_home(home: &Path) {
        fs::create_dir_all(home.join("wal")).unwrap();
        let (writer, join) =
            crate::wal::writer::spawn_for_home(home.join("wal/000001.wal"), home.to_path_buf())
                .unwrap();
        let payload = request();
        writer
            .append_authenticated(
                crate::wal::HeaderBuilder::new(
                    crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST,
                    &payload,
                )
                .build(),
                payload,
            )
            .await
            .unwrap();
        let payload = acquisition();
        writer
            .append_authenticated(
                crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_EXTENDED, &payload)
                    .event_subtype(
                        crate::wal::events::ExtendedSubtype::ProviderBudgetAcquired as u8,
                    )
                    .build(),
                payload,
            )
            .await
            .unwrap();
        // An unrelated frame carrying similar JSON must never become an observation.
        let payload = acquisition();
        writer
            .append_authenticated(
                crate::wal::HeaderBuilder::new(
                    crate::wal::events::EVENT_TYPE_PROVIDER_RESPONSE,
                    &payload,
                )
                .build(),
                payload,
            )
            .await
            .unwrap();
        drop(writer);
        tokio::time::timeout(Duration::from_secs(5), join)
            .await
            .unwrap()
            .unwrap();
    }

    fn snapshot(root: &Path) -> BTreeMap<std::path::PathBuf, Vec<u8>> {
        fn collect(root: &Path, path: &Path, files: &mut BTreeMap<std::path::PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(path).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    collect(root, &path, files);
                } else {
                    files.insert(
                        path.strip_prefix(root).unwrap().to_path_buf(),
                        fs::read(path).unwrap(),
                    );
                }
            }
        }
        let mut files = BTreeMap::new();
        collect(root, root, &mut files);
        files
    }

    #[test]
    fn absent_home_retains_unknown_history_without_creating_files() {
        let home = tempfile::tempdir().unwrap();
        let inspection = inspect(home.path(), 0, 20).unwrap();
        assert!(inspection.no_retained_segments);
        assert!(!inspection.full_history_complete);
        assert!(inspection.observations.groups.is_empty());
        assert!(fs::read_dir(home.path()).unwrap().next().is_none());
    }

    #[tokio::test]
    async fn real_authenticated_wal_binds_observations_and_leaves_home_unchanged() {
        let home = tempfile::tempdir().unwrap();
        real_home(home.path()).await;
        fs::create_dir_all(home.path().join("usage")).unwrap();
        fs::write(
            home.path().join("usage/sentinel.jsonl"),
            b"not parsed or repaired\n",
        )
        .unwrap();
        let before = snapshot(home.path());
        let inspection = inspect(home.path(), 10, 11).unwrap();
        assert_eq!(inspection.observations.groups.len(), 1);
        let group = &inspection.observations.groups[0];
        assert_eq!(group.association, collector::Association::Matched);
        assert_eq!(group.requests.len(), 1);
        assert_eq!(group.acquisitions.len(), 1);
        assert_eq!(
            group.acquisitions[0].record.daily_reserved_usd_nanos,
            Some(0)
        );
        assert_eq!(group.acquisitions[0].location.segment_name, "000001.wal");
        let value: Value =
            serde_json::from_str(&render(&inspection, UsageFormat::Json).unwrap()).unwrap();
        assert_eq!(value["schema"], "neoth.provider-acquisition-inspection.v1");
        assert_eq!(value["full_history_complete"], false);
        assert!(!value.to_string().contains("never-include-this-content"));
        assert_eq!(snapshot(home.path()), before);
    }

    #[tokio::test]
    async fn changed_verification_key_returns_no_inspection() {
        let home = tempfile::tempdir().unwrap();
        real_home(home.path()).await;
        fs::write(home.path().join("wal/hmac.key"), [0x19u8; 32]).unwrap();
        assert!(inspect(home.path(), 0, 20).is_err());
    }

    #[test]
    fn error_after_valid_callback_discards_all_buffered_observations() {
        let result = collect_after_scan(0, 20, |collector| {
            collector.ingest_request(
                Location {
                    segment_name: "000001.wal".into(),
                    segment_generation: 1,
                    segment_seq: 1,
                    segment_start_ts_ns: 0,
                    segment_node_id: [0; 16],
                    logical_offset: 64,
                },
                &request(),
            )?;
            bail!("injected later authentication failure")
        });
        assert!(result.is_err());
    }

    #[test]
    fn incomplete_prefix_does_not_turn_unseen_acquisition_into_zero() {
        // The scanner itself tests real keyed-marker tail exclusion. This seam
        // checks that the reader preserves its incomplete-coverage result.
        let inspection = collect_after_scan(0, 20, |collector| {
            collector.ingest_request(
                Location {
                    segment_name: "000001.wal".into(),
                    segment_generation: 1,
                    segment_seq: 1,
                    segment_start_ts_ns: 0,
                    segment_node_id: [0; 16],
                    logical_offset: 64,
                },
                &request(),
            )?;
            Ok(AuthenticatedPrefixScan {
                complete: false,
                boundaries: vec![crate::wal::scan::AuthenticatedPrefixBoundary {
                    segment_name: "000001.wal".into(),
                    authenticated_through: 128,
                    logical_len: 256,
                }],
            })
        })
        .unwrap();
        assert!(!inspection.scan.complete);
        assert_eq!(
            inspection.observations.groups[0].association,
            collector::Association::RequestOnly
        );
        assert!(inspection.observations.groups[0].acquisitions.is_empty());
        assert!(!inspection.full_history_complete);
    }

    #[test]
    fn output_limit_is_enforced_before_extending_the_buffer() {
        let mut output = BoundedOutput {
            bytes: Vec::new(),
            limit: 4,
        };
        output.write_all(b"1234").unwrap();
        assert!(output.write_all(b"5").is_err());
        assert_eq!(output.bytes, b"1234");
    }

    #[test]
    fn cli_mode_defaults_and_currency_conflict_are_explicit() {
        let legacy = TestCli::try_parse_from(["test"]).unwrap().args;
        assert!(!legacy.acquisitions);
        assert_eq!(legacy.format, "table");
        assert_eq!(legacy.days, 1);
        let legacy_currency = TestCli::try_parse_from(["test", "--currency", "EUR"])
            .unwrap()
            .args;
        assert!(!legacy_currency.acquisitions);
        assert_eq!(legacy_currency.currency.as_deref(), Some("EUR"));
        assert!(TestCli::try_parse_from(["test", "--acquisitions", "--currency", "EUR"]).is_err());
        assert!(
            TestCli::try_parse_from(["test", "--acquisitions"])
                .unwrap()
                .args
                .acquisitions
        );
    }

    #[test]
    fn explicit_window_never_reads_the_clock_and_keeps_inclusive_bounds() {
        let args = TestCli::try_parse_from([
            "test",
            "--acquisitions",
            "--since-unix",
            "10",
            "--until-unix",
            "20",
        ])
        .unwrap()
        .args;
        assert_eq!(
            window(&args, || panic!("explicit interval must not read clock")).unwrap(),
            (10, 20)
        );
        let mut invalid = args.clone();
        invalid.since_unix = Some(21);
        assert!(window(&invalid, || Ok(0)).is_err());
        invalid.since_unix = Some(-1);
        assert!(window(&invalid, || Ok(0)).is_err());
    }

    #[test]
    fn default_window_uses_checked_subtraction() {
        let args = TestCli::try_parse_from(["test", "--acquisitions"])
            .unwrap()
            .args;
        assert_eq!(window(&args, || Ok(100_000)).unwrap(), (13_600, 100_000));
        assert!(window(&args, || Ok(i64::MIN)).is_err());
    }
}
