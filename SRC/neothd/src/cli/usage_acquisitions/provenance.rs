//! Read-only comparison of retained invocation metadata, never budget authority.
mod decode;
#[cfg(test)]
mod tests;
mod unique_json;

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::Serialize;

use super::collector::{self, Acquisition, Diagnostic, Limits, Located, Location, Request};
use super::{BoundedOutput, MAX_OUTPUT_BYTES, location, window};
use crate::cli::usage::{UsageArgs, UsageFormat};
use crate::wal::events::{
    EVENT_TYPE_COST_ESTIMATE_SHOWN, EVENT_TYPE_EXTENDED, EVENT_TYPE_PROVIDER_ERROR,
    EVENT_TYPE_PROVIDER_REQUEST, EVENT_TYPE_PROVIDER_RESPONSE, ExtendedSubtype,
};
use crate::wal::scan::AuthenticatedPrefixScan;
use decode::{Plan, Terminal};

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Association {
    ObservedMetadataMatch,
    #[default]
    Incomplete,
    Unbound,
    Duplicate,
    Conflict,
}

#[derive(Default, Debug, Serialize)]
struct Group {
    invocation_id: String,
    association: Association,
    missing_kinds: Vec<&'static str>,
    duplicate_kinds: Vec<&'static str>,
    difference_fields: BTreeSet<&'static str>,
    unbound_terminal_present: bool,
    requests: Vec<Located<Request>>,
    plans: Vec<Located<Plan>>,
    acquisitions: Vec<Located<Acquisition>>,
    terminals: Vec<Located<Terminal>>,
}

#[derive(Debug, Serialize)]
struct Observations {
    since_unix: u64,
    until_unix: u64,
    semantic_decode_complete: bool,
    groups: Vec<Group>,
    diagnostics: Vec<Diagnostic>,
}

struct Collector {
    base: collector::Collector,
    extra: BTreeMap<String, Group>,
}

impl Collector {
    fn new(limits: Limits) -> Self {
        Self {
            base: collector::Collector::new(limits),
            extra: BTreeMap::new(),
        }
    }

    fn ingest(
        &mut self,
        event_type: u8,
        subtype: u8,
        location: Location,
        payload: &[u8],
    ) -> Result<()> {
        let kind = match event_type {
            EVENT_TYPE_PROVIDER_REQUEST => "request",
            EVENT_TYPE_COST_ESTIMATE_SHOWN => "plan",
            EVENT_TYPE_PROVIDER_RESPONSE | EVENT_TYPE_PROVIDER_ERROR => "terminal",
            EVENT_TYPE_EXTENDED if subtype == ExtendedSubtype::ProviderBudgetAcquired as u8 => {
                "acquisition"
            }
            _ => return Ok(()),
        };
        // One shared charge per recognized frame, before any JSON allocation.
        self.base.charge(&location, payload)?;
        match kind {
            "request" | "acquisition" => {
                let value = match unique_json::parse_unique_json(payload) {
                    Ok(value) => value,
                    Err(_) => return self.base.diagnostic(location, kind, "malformed"),
                };
                if kind == "request"
                    && value.get("model").is_some_and(|model| {
                        model.as_str().is_none()
                            || model.as_str()
                                != value.get("wire_model").and_then(serde_json::Value::as_str)
                    })
                {
                    return self.base.diagnostic(location, kind, "malformed");
                }
                if kind == "request" {
                    self.base.ingest_charged_request(location, payload)
                } else {
                    self.base.ingest_charged_acquisition(location, payload)
                }
            }
            "plan" => match decode::plan(payload) {
                Ok(record) => {
                    self.extra
                        .entry(record.invocation_id.clone())
                        .or_default()
                        .plans
                        .push(Located {
                            location,
                            is_in_window: false,
                            record,
                        });
                    Ok(())
                }
                Err(code) => self.base.diagnostic(location, kind, code),
            },
            _ => match decode::terminal(event_type, payload) {
                Ok(record) => {
                    self.extra
                        .entry(record.invocation_id.clone())
                        .or_default()
                        .terminals
                        .push(Located {
                            location,
                            is_in_window: false,
                            record,
                        });
                    Ok(())
                }
                Err(code) => self.base.diagnostic(location, kind, code),
            },
        }
    }

    fn finish(self, since: u64, until: u64) -> Result<Observations> {
        if since > until {
            bail!("invalid provenance time range");
        }
        // Do not discard a request/acquisition merely because only its terminal is in-window.
        let base = self.base.finish(0, u64::MAX)?;
        let mut merged = self.extra;
        for original in base.groups {
            let group = merged.entry(original.invocation_id).or_default();
            group.requests = original.requests;
            group.acquisitions = original.acquisitions;
            group.difference_fields.extend(original.difference_fields);
        }
        let mut groups = Vec::new();
        for (id, mut group) in merged {
            group.invocation_id = id;
            let requested = mark_window(&mut group.requests, since, until, |v| v.ts_unix);
            let planned = mark_window(&mut group.plans, since, until, |v| v.ts_unix);
            let acquired = mark_window(&mut group.acquisitions, since, until, |v| v.ts_unix);
            let terminal = mark_window(&mut group.terminals, since, until, |v| v.ts_unix);
            if !(requested || planned || acquired || terminal) {
                continue;
            }
            group.classify();
            groups.push(group);
        }
        Ok(Observations {
            since_unix: since,
            until_unix: until,
            semantic_decode_complete: base.semantic_decode_complete,
            groups,
            diagnostics: base.diagnostics,
        })
    }
}

fn mark_window<T>(
    records: &mut [Located<T>],
    since: u64,
    until: u64,
    time: impl Fn(&T) -> u64,
) -> bool {
    for value in records.iter_mut() {
        value.is_in_window = (since..=until).contains(&time(&value.record));
    }
    records.iter().any(|value| value.is_in_window)
}

fn differ<T: PartialEq>(records: &[Located<T>]) -> bool {
    records
        .first()
        .is_some_and(|first| records.iter().any(|value| value.record != first.record))
}

impl Group {
    fn classify(&mut self) {
        for (kind, count, differs) in [
            ("request", self.requests.len(), differ(&self.requests)),
            ("plan", self.plans.len(), differ(&self.plans)),
            (
                "acquisition",
                self.acquisitions.len(),
                differ(&self.acquisitions),
            ),
            ("terminal", self.terminals.len(), differ(&self.terminals)),
        ] {
            if count == 0 {
                self.missing_kinds.push(kind);
            } else if count > 1 {
                self.duplicate_kinds.push(kind);
            }
            if differs {
                self.difference_fields.insert(kind);
            }
        }
        // All valid occurrences participate; no winner is selected on conflicts.
        let identities = self
            .requests
            .iter()
            .map(|v| {
                (
                    Some(v.record.request_binding_sha256.as_str()),
                    v.record.provider.as_str(),
                    v.record.wire_model.as_str(),
                )
            })
            .chain(self.plans.iter().map(|v| {
                (
                    Some(v.record.binding.as_str()),
                    v.record.provider.as_str(),
                    v.record.wire_model.as_str(),
                )
            }))
            .chain(self.acquisitions.iter().map(|v| {
                (
                    Some(v.record.request_binding_sha256.as_str()),
                    v.record.provider.as_str(),
                    v.record.wire_model.as_str(),
                )
            }))
            .chain(self.terminals.iter().map(|v| {
                (
                    if v.record.lifecycle_bound {
                        v.record.binding.as_deref()
                    } else {
                        None
                    },
                    v.record.provider.as_str(),
                    v.record.wire_model.as_str(),
                )
            }));
        let mut bindings = BTreeSet::new();
        let mut providers = BTreeSet::new();
        let mut models = BTreeSet::new();
        for (binding, provider, model) in identities {
            if let Some(binding) = binding {
                bindings.insert(binding);
            }
            providers.insert(provider);
            models.insert(model);
        }
        for (field, count) in [
            ("request_binding_sha256", bindings.len()),
            ("provider", providers.len()),
            ("wire_model", models.len()),
        ] {
            if count > 1 {
                self.difference_fields.insert(field);
            }
        }
        self.unbound_terminal_present = self
            .terminals
            .iter()
            .any(|v| !v.record.lifecycle_bound || v.record.binding.is_none());
        self.association = if !self.difference_fields.is_empty() {
            Association::Conflict
        } else if !self.duplicate_kinds.is_empty() {
            Association::Duplicate
        } else if self.unbound_terminal_present {
            Association::Unbound
        } else if !self.missing_kinds.is_empty() {
            Association::Incomplete
        } else {
            Association::ObservedMetadataMatch
        };
    }
}

#[derive(Serialize)]
struct Inspection {
    schema: &'static str,
    scope: &'static str,
    association_semantics: &'static str,
    status_precedence: &'static str,
    time_filter: &'static str,
    units_and_unknowns: &'static str,
    input_estimator: &'static str,
    tokenizer_version: Option<&'static str>,
    full_history_complete: bool,
    atomic_latest_snapshot: bool,
    scan: AuthenticatedPrefixScan,
    observations: Observations,
}

fn collect_after_scan<F>(since: u64, until: u64, scan: F) -> Result<Inspection>
where
    F: FnOnce(&mut Collector) -> Result<AuthenticatedPrefixScan>,
{
    if since > until {
        bail!("provenance start must not be after end");
    }
    let mut collector = Collector::new(Limits {
        max_records: 20_000,
        max_diagnostics: 1_000,
        max_input_bytes: 8 * 1024 * 1024,
    });
    // A failed scan/callback exposes no partial observations.
    let scan = scan(&mut collector)?;
    let observations = collector.finish(since, until)?;
    Ok(Inspection {
        schema: "neoth.provider-provenance-inspection.v1",
        scope: "retained_authenticated_wal_prefix",
        association_semantics: "one_observed_record_per_kind_with_equal_binding_provider_model_not_causality_uniqueness_or_history_completeness",
        status_precedence: "conflict_duplicate_unbound_incomplete_observed_metadata_match",
        time_filter: "any_recorded_timestamp_inclusive_with_all_context_labeled",
        units_and_unknowns: "plans_estimate_reservations_acquire_provider_counters_observe_frozen_costs_compute_not_invoices_or_balances_null_unknown_zero_known",
        input_estimator: "utf8_bytes_plus_request_message_overhead_not_model_tokenizer",
        tokenizer_version: None,
        full_history_complete: false,
        atomic_latest_snapshot: false,
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
                collector.ingest(
                    frame.header.event_type,
                    frame.header.event_subtype,
                    location(source),
                    frame.payload,
                )
            },
        )
    })
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
                "Invocation provenance [{} .. {}] (inclusive recorded timestamps)",
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
                "Metadata matches cover observed records only; this is not complete history or an atomic latest view."
            )?;
            writeln!(
                output,
                "Plans are estimates; acquisitions are reservations; terminal counters are provider reports."
            )?;
            writeln!(
                output,
                "Frozen computed costs are not invoices or current balances. null stays unknown; zero stays known."
            )?;
            writeln!(
                output,
                "Prompt components use a UTF-8 upper-bound estimate, not a model tokenizer; tokenizer version is unknown."
            )?;
            if inspection.scan.boundaries.is_empty() {
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
                    "\nInvocation {:?}: {:?}; missing={:?} duplicates={:?} differences={:?} unbound_terminal={}",
                    group.invocation_id,
                    group.association,
                    group.missing_kinds,
                    group.duplicate_kinds,
                    group.difference_fields,
                    group.unbound_terminal_present
                )?;
                for value in &group.requests {
                    write!(output, "  request ")?;
                    serde_json::to_writer(&mut output, value)?;
                    writeln!(output)?;
                }
                for value in &group.plans {
                    write!(output, "  planned estimate ")?;
                    serde_json::to_writer(&mut output, value)?;
                    writeln!(output)?;
                }
                for value in &group.acquisitions {
                    write!(output, "  acquired scopes ")?;
                    serde_json::to_writer(&mut output, value)?;
                    writeln!(output)?;
                }
                for value in &group.terminals {
                    write!(output, "  provider counters and frozen computation ")?;
                    serde_json::to_writer(&mut output, value)?;
                    writeln!(output)?;
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
    String::from_utf8(output.bytes).context("encode provenance inspection")
}

pub(in crate::cli) fn run(home: &Path, args: UsageArgs) -> Result<()> {
    if args.currency.is_some() || args.acquisitions {
        bail!("--provenance cannot be combined with --acquisitions or --currency");
    }
    let format =
        UsageFormat::parse(&args.format).context("provenance format must be table or json")?;
    let (since, until) = window(&args, || {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock before unix epoch")?
            .as_secs();
        i64::try_from(seconds).context("system clock exceeds timestamp range")
    })?;
    let text = render(&inspect(home, since, until)?, format)?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(text.as_bytes())?;
    stdout.flush()?;
    Ok(())
}
