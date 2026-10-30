//! Decode and compare acquisition observations within one authenticated WAL scan.
//! Matching is not budget authority, spending, settlement or complete history.
use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::{Deserialize, Deserializer, Serialize};

const ACQ_SCHEMA: &str = "neoth.provider-budget-acquired.v1";
const REQUEST_SCHEMA: &str = "neoth.provider-lifecycle.v1";

#[derive(Clone, Debug, Serialize)]
pub(super) struct Location {
    pub segment_name: String,
    pub segment_generation: u32,
    pub segment_seq: u64,
    pub segment_start_ts_ns: u64,
    pub segment_node_id: [u8; 16],
    pub logical_offset: u64,
}

fn required_option<'de, D, T>(d: D) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Operation {
    pub reserved_tokens: u64,
    pub reserved_microusd: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Cluster {
    pub reserved_usd_nanos: u64,
    pub grant_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Acquisition {
    pub schema: String,
    pub invocation_id: String,
    pub request_binding_sha256: String,
    pub provider: String,
    pub wire_model: String,
    pub ts_unix: u64,
    #[serde(deserialize_with = "required_option")]
    pub daily_reserved_usd_nanos: Option<u64>,
    #[serde(deserialize_with = "required_option")]
    pub operation: Option<Operation>,
    #[serde(deserialize_with = "required_option")]
    pub cluster: Option<Cluster>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(super) struct Request {
    pub schema: String,
    pub invocation_id: String,
    pub request_binding_sha256: String,
    pub provider: String,
    pub wire_model: String,
    pub ts_unix: u64,
}

#[derive(Deserialize)]
struct Header {
    schema: String,
}

#[derive(Deserialize)]
struct RequestSchema {
    schema: Option<String>,
}

#[derive(Deserialize)]
struct RequestProbe {
    schema: String,
    invocation_id: Option<String>,
    request_binding_sha256: Option<String>,
    provider: Option<String>,
    wire_model: Option<String>,
    ts_unix: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(super) struct Located<T> {
    pub location: Location,
    pub is_in_window: bool,
    pub record: T,
}

#[derive(Debug, Serialize)]
pub(super) struct Diagnostic {
    pub location: Location,
    pub record_kind: &'static str,
    pub code: &'static str,
}

/// Comparison of valid observed records only; missing counterparts stay unknown.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Association {
    Matched,
    RequestOnly,
    AcquisitionOnly,
    Duplicate,
    Conflict,
}

#[derive(Debug, Serialize)]
pub(super) struct Group {
    pub invocation_id: String,
    pub association: Association,
    /// Deterministic observed field differences, never proof of a budget discrepancy.
    pub difference_fields: Vec<&'static str>,
    pub requests: Vec<Located<Request>>,
    pub acquisitions: Vec<Located<Acquisition>>,
}

#[derive(Debug, Serialize)]
pub(super) struct Report {
    pub since_unix: u64,
    pub until_unix: u64,
    /// Only decoding of recognized records in this scan, never history completeness.
    pub semantic_decode_complete: bool,
    pub groups: Vec<Group>,
    /// Scan-wide: malformed records have no trusted timestamp for time filtering.
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub max_records: usize,
    pub max_diagnostics: usize,
    pub max_input_bytes: usize,
}

#[derive(Default)]
struct Pending {
    requests: Vec<Located<Request>>,
    acquisitions: Vec<Located<Acquisition>>,
}

pub(super) struct Collector {
    limits: Limits,
    records: usize,
    input_bytes: usize,
    poisoned: bool,
    groups: BTreeMap<String, Pending>,
    diagnostics: Vec<Diagnostic>,
}

pub(super) fn identity_ok(id: &str, hash: &str, provider: &str, model: &str) -> bool {
    id.len() == 64
        && id.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && hash.len() == 64
        && hash.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && !provider.trim().is_empty()
        && !model.trim().is_empty()
}

impl Collector {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            records: 0,
            input_bytes: 0,
            poisoned: false,
            groups: BTreeMap::new(),
            diagnostics: Vec::new(),
        }
    }

    pub(super) fn charge(&mut self, location: &Location, payload: &[u8]) -> Result<()> {
        if self.poisoned {
            bail!("acquisition collector poisoned");
        }
        let records = self.records.checked_add(1);
        let bytes = payload.len().checked_add(location.segment_name.len())
            .and_then(|size| self.input_bytes.checked_add(size));
        match (records, bytes) {
            (Some(records), Some(bytes))
                if location.segment_name.len() <= 255
                    && records <= self.limits.max_records
                    && bytes <= self.limits.max_input_bytes =>
            {
                self.records = records;
                self.input_bytes = bytes;
                Ok(())
            }
            _ => {
                self.poisoned = true;
                bail!("acquisition input limit exceeded")
            }
        }
    }

    pub(super) fn diagnostic(&mut self, location: Location, kind: &'static str, code: &'static str) -> Result<()> {
        if self.diagnostics.len() >= self.limits.max_diagnostics {
            self.poisoned = true;
            bail!("acquisition diagnostic limit exceeded");
        }
        self.diagnostics.push(Diagnostic { location, record_kind: kind, code });
        Ok(())
    }

    pub fn ingest_request(&mut self, location: Location, payload: &[u8]) -> Result<()> {
        self.charge(&location, payload)?;
        self.ingest_charged_request(location, payload)
    }

    pub(super) fn ingest_charged_request(&mut self, location: Location, payload: &[u8]) -> Result<()> {
        let header: RequestSchema = match serde_json::from_slice(payload) {
            Ok(value) => value,
            Err(_) => return self.diagnostic(location, "request", "malformed"),
        };
        let Some(schema) = header.schema else {
            return self.diagnostic(location, "request", "legacy_schema_unknown");
        };
        if schema != REQUEST_SCHEMA {
            return self.diagnostic(location, "request", "unsupported_schema");
        }
        let probe: RequestProbe = match serde_json::from_slice(payload) {
            Ok(value) => value,
            Err(_) => return self.diagnostic(location, "request", "malformed"),
        };
        let (invocation_id, request_binding_sha256, provider, wire_model, ts_unix) =
            match (probe.invocation_id, probe.request_binding_sha256, probe.provider,
                probe.wire_model, probe.ts_unix) {
                (Some(id), Some(hash), Some(provider), Some(model), Some(time)) =>
                    (id, hash, provider, model, time),
                _ => return self.diagnostic(location, "request", "legacy_identity_unknown"),
            };
        if !identity_ok(&invocation_id, &request_binding_sha256, &provider, &wire_model) {
            return self.diagnostic(location, "request", "malformed");
        }
        let record = Request {
            schema: probe.schema, invocation_id, request_binding_sha256, provider, wire_model, ts_unix,
        };
        self.groups.entry(record.invocation_id.clone()).or_default().requests.push(Located {
            location, is_in_window: false, record,
        });
        Ok(())
    }

    pub fn ingest_acquisition(&mut self, location: Location, payload: &[u8]) -> Result<()> {
        self.charge(&location, payload)?;
        self.ingest_charged_acquisition(location, payload)
    }

    pub(super) fn ingest_charged_acquisition(&mut self, location: Location, payload: &[u8]) -> Result<()> {
        let header: Header = match serde_json::from_slice(payload) {
            Ok(value) => value,
            Err(_) => return self.diagnostic(location, "acquisition", "malformed"),
        };
        if header.schema != ACQ_SCHEMA {
            return self.diagnostic(location, "acquisition", "unsupported_schema");
        }
        let record: Acquisition = match serde_json::from_slice(payload) {
            Ok(value) => value,
            Err(_) => return self.diagnostic(location, "acquisition", "malformed"),
        };
        if !identity_ok(&record.invocation_id, &record.request_binding_sha256,
                &record.provider, &record.wire_model)
            || (record.daily_reserved_usd_nanos.is_none()
                && record.operation.is_none() && record.cluster.is_none())
            || record.cluster.as_ref().is_some_and(|cluster| cluster.grant_id.trim().is_empty())
        {
            return self.diagnostic(location, "acquisition", "malformed");
        }
        self.groups.entry(record.invocation_id.clone()).or_default().acquisitions.push(Located {
            location, is_in_window: false, record,
        });
        Ok(())
    }

    pub fn finish(self, since: u64, until: u64) -> Result<Report> {
        if self.poisoned {
            bail!("acquisition collector poisoned");
        }
        if since > until {
            bail!("invalid acquisition time range");
        }
        let semantic_decode_complete = self.diagnostics.is_empty();
        let mut groups = Vec::new();
        for (invocation_id, pending) in self.groups {
            let mut requests = pending.requests;
            let mut acquisitions = pending.acquisitions;
            for request in &mut requests {
                request.is_in_window = (since..=until).contains(&request.record.ts_unix);
            }
            for acquisition in &mut acquisitions {
                acquisition.is_in_window = (since..=until).contains(&acquisition.record.ts_unix);
            }
            if !requests.iter().any(|request| request.is_in_window)
                && !acquisitions.iter().any(|acquisition| acquisition.is_in_window)
            {
                continue;
            }
            let mut difference_fields = Vec::new();
            if let Some(first) = requests.first() {
                for (field, differs) in [
                    ("request.request_binding_sha256", requests.iter().any(|value| value.record.request_binding_sha256 != first.record.request_binding_sha256)),
                    ("request.provider", requests.iter().any(|value| value.record.provider != first.record.provider)),
                    ("request.wire_model", requests.iter().any(|value| value.record.wire_model != first.record.wire_model)),
                    ("request.ts_unix", requests.iter().any(|value| value.record.ts_unix != first.record.ts_unix)),
                ] {
                    if differs {
                        difference_fields.push(field);
                    }
                }
            }
            if let Some(first) = acquisitions.first() {
                for (field, differs) in [
                    ("acquisition.request_binding_sha256", acquisitions.iter().any(|value| value.record.request_binding_sha256 != first.record.request_binding_sha256)),
                    ("acquisition.provider", acquisitions.iter().any(|value| value.record.provider != first.record.provider)),
                    ("acquisition.wire_model", acquisitions.iter().any(|value| value.record.wire_model != first.record.wire_model)),
                    ("acquisition.ts_unix", acquisitions.iter().any(|value| value.record.ts_unix != first.record.ts_unix)),
                    ("acquisition.daily_reserved_usd_nanos", acquisitions.iter().any(|value| value.record.daily_reserved_usd_nanos != first.record.daily_reserved_usd_nanos)),
                    ("acquisition.operation", acquisitions.iter().any(|value| value.record.operation != first.record.operation)),
                    ("acquisition.cluster", acquisitions.iter().any(|value| value.record.cluster != first.record.cluster)),
                ] {
                    if differs {
                        difference_fields.push(field);
                    }
                }
            }
            if let (Some(request), Some(acquisition)) = (requests.first(), acquisitions.first()) {
                for (field, differs) in [
                    ("request_vs_acquisition.request_binding_sha256", request.record.request_binding_sha256 != acquisition.record.request_binding_sha256),
                    ("request_vs_acquisition.provider", request.record.provider != acquisition.record.provider),
                    ("request_vs_acquisition.wire_model", request.record.wire_model != acquisition.record.wire_model),
                ] {
                    if differs {
                        difference_fields.push(field);
                    }
                }
            }
            let association = if !difference_fields.is_empty() {
                Association::Conflict
            } else if requests.len() > 1 || acquisitions.len() > 1 {
                Association::Duplicate
            } else if requests.is_empty() {
                Association::AcquisitionOnly
            } else if acquisitions.is_empty() {
                Association::RequestOnly
            } else {
                Association::Matched
            };
            groups.push(Group { invocation_id, association, difference_fields, requests, acquisitions });
        }
        Ok(Report {
            since_unix: since, until_unix: until, semantic_decode_complete,
            groups, diagnostics: self.diagnostics,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn location() -> Location {
        Location {
            segment_name: "000001.wal".into(), segment_generation: 1,
            segment_seq: 2, segment_start_ts_ns: 3,
            segment_node_id: [0; 16], logical_offset: 4,
        }
    }
    fn limits() -> Limits {
        Limits { max_records: 100, max_diagnostics: 100, max_input_bytes: 100_000 }
    }
    fn acquisition() -> Value {
        json!({
            "schema": ACQ_SCHEMA, "invocation_id": "b".repeat(64), "request_binding_sha256": "a".repeat(64),
            "provider": "p", "wire_model": "m", "ts_unix": 10,
            "daily_reserved_usd_nanos": 0, "operation": null, "cluster": null,
        })
    }
    fn request() -> Value {
        json!({
            "schema": REQUEST_SCHEMA, "invocation_id": "b".repeat(64), "request_binding_sha256": "a".repeat(64),
            "provider": "p", "wire_model": "m", "ts_unix": 10, "extra": "not retained",
        })
    }
    fn bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }
    fn one(value: &Value) -> Report {
        let mut collector = Collector::new(limits());
        collector.ingest_acquisition(location(), &bytes(value)).unwrap();
        collector.finish(0, 20).unwrap()
    }
    pub(super) fn diagnostic(value: &Value, code: &str) {
        let report = one(value);
        assert!(!report.semantic_decode_complete);
        assert_eq!(report.diagnostics.len(), 1);
        assert_eq!(report.diagnostics[0].code, code);
    }
    #[test]
    fn explicit_zero_and_null_are_preserved() {
        let report = one(&acquisition());
        let record = &report.groups[0].acquisitions[0].record;
        assert_eq!(record.daily_reserved_usd_nanos, Some(0));
        assert!(record.operation.is_none());
        assert!(record.cluster.is_none());
        assert!(report.semantic_decode_complete);
    }
    #[test]
    fn missing_nullable_is_malformed() {
        for name in ["daily_reserved_usd_nanos", "operation", "cluster"] {
            let mut value = acquisition();
            value.as_object_mut().unwrap().remove(name);
            diagnostic(&value, "malformed");
        }
    }
    #[test]
    fn all_null_is_malformed() {
        let mut value = acquisition();
        value["daily_reserved_usd_nanos"] = Value::Null;
        diagnostic(&value, "malformed");
    }
    #[test]
    fn zero_nested_amounts_are_valid() {
        let mut value = acquisition();
        value["daily_reserved_usd_nanos"] = Value::Null;
        value["operation"] = json!({"reserved_tokens": 0, "reserved_microusd": 0});
        value["cluster"] = json!({"reserved_usd_nanos": 0, "grant_id": "g"});
        let report = one(&value);
        assert!(report.semantic_decode_complete);
        assert_eq!(report.groups[0].acquisitions[0].record.operation.as_ref().unwrap().reserved_tokens, 0);
    }
    #[test]
    fn wrong_types_and_extra_fields_are_malformed_without_payload_leak() {
        for amount in [json!("0"), json!(-1), json!(0.5)] {
            let mut value = acquisition();
            value["daily_reserved_usd_nanos"] = amount;
            diagnostic(&value, "malformed");
        }
        let mut value = acquisition();
        value["extra"] = json!("secret-marker");
        let report = one(&value);
        assert!(!report.semantic_decode_complete);
        assert!(!serde_json::to_string(&report).unwrap().contains("secret-marker"));
    }
    #[test]
    fn duplicate_known_json_keys_are_malformed() {
        for prefix in [r#"{"invocation_id":"other","#, r#"{"schema":"future","#] {
            let raw = String::from_utf8(bytes(&acquisition())).unwrap().replacen('{', prefix, 1);
            let mut collector = Collector::new(limits());
            collector.ingest_acquisition(location(), raw.as_bytes()).unwrap();
            assert_eq!(collector.finish(0, 20).unwrap().diagnostics[0].code, "malformed");
        }
    }
    #[test]
    fn unsupported_schema_is_explicit_before_current_field_types() {
        let mut value = acquisition();
        value["schema"] = json!("future");
        diagnostic(&value, "unsupported_schema");
        let mut value = request();
        value["schema"] = json!("future");
        value["ts_unix"] = json!("new representation");
        let mut collector = Collector::new(limits());
        collector.ingest_request(location(), &bytes(&value)).unwrap();
        assert_eq!(collector.finish(0, 20).unwrap().diagnostics[0].code, "unsupported_schema");
    }
    #[test]
    fn legacy_request_is_unknown() {
        let mut value = request();
        value.as_object_mut().unwrap().remove("request_binding_sha256");
        let mut collector = Collector::new(limits());
        collector.ingest_request(location(), &bytes(&value)).unwrap();
        let report = collector.finish(0, 20).unwrap();
        assert!(!report.semantic_decode_complete);
        assert_eq!(report.diagnostics[0].code, "legacy_identity_unknown");
        assert!(report.groups.is_empty());
    }
    #[test]
    fn unmatched_records_are_explicit() {
        assert_eq!(one(&acquisition()).groups[0].association, Association::AcquisitionOnly);
        let mut collector = Collector::new(limits());
        collector.ingest_request(location(), &bytes(&request())).unwrap();
        assert_eq!(collector.finish(0, 20).unwrap().groups[0].association, Association::RequestOnly);
    }
    #[test]
    fn single_compatible_pair_matches_without_retaining_request_extras() {
        let mut collector = Collector::new(limits());
        collector.ingest_request(location(), &bytes(&request())).unwrap();
        collector.ingest_acquisition(location(), &bytes(&acquisition())).unwrap();
        let report = collector.finish(0, 20).unwrap();
        assert_eq!(report.groups[0].association, Association::Matched);
        assert!(!serde_json::to_string(&report).unwrap().contains("not retained"));
    }
    #[test]
    fn identical_occurrences_are_duplicates() {
        let mut collector = Collector::new(limits());
        let payload = bytes(&acquisition());
        collector.ingest_acquisition(location(), &payload).unwrap();
        collector.ingest_acquisition(location(), &payload).unwrap();
        assert_eq!(collector.finish(0, 20).unwrap().groups[0].association, Association::Duplicate);
    }
    #[test]
    fn conflict_outside_window_remains_visible() {
        let mut later = acquisition();
        later["ts_unix"] = json!(100);
        later["daily_reserved_usd_nanos"] = json!(1);
        let mut collector = Collector::new(limits());
        collector.ingest_acquisition(location(), &bytes(&acquisition())).unwrap();
        collector.ingest_acquisition(location(), &bytes(&later)).unwrap();
        let report = collector.finish(10, 10).unwrap();
        let group = &report.groups[0];
        assert_eq!(group.association, Association::Conflict);
        assert!(group.acquisitions[0].is_in_window);
        assert!(!group.acquisitions[1].is_in_window);
    }
    #[test]
    fn union_window_includes_context_and_endpoints() {
        let mut later = acquisition();
        later["ts_unix"] = json!(21);
        let mut earlier = request();
        earlier["ts_unix"] = json!(20);
        let mut collector = Collector::new(limits());
        collector.ingest_request(location(), &bytes(&earlier)).unwrap();
        collector.ingest_acquisition(location(), &bytes(&later)).unwrap();
        let report = collector.finish(10, 20).unwrap();
        assert!(report.groups[0].requests[0].is_in_window);
        assert!(!report.groups[0].acquisitions[0].is_in_window);
        assert!(Collector::new(limits()).finish(20, 10).is_err());
    }
    #[test]
    fn record_and_byte_limits_poison_future_readout() {
        let mut bounds = limits();
        bounds.max_records = 1;
        let mut collector = Collector::new(bounds);
        let payload = bytes(&acquisition());
        collector.ingest_acquisition(location(), &payload).unwrap();
        assert!(collector.ingest_acquisition(location(), &payload).is_err());
        assert!(collector.finish(0, 20).is_err());
        let mut bounds = limits();
        bounds.max_input_bytes = payload.len() + location().segment_name.len() - 1;
        let mut collector = Collector::new(bounds);
        assert!(collector.ingest_acquisition(location(), &payload).is_err());
        assert!(collector.finish(0, 20).is_err());
    }
    #[test]
    fn diagnostic_and_location_limits_poison_future_readout() {
        let mut bounds = limits();
        bounds.max_diagnostics = 1;
        let mut collector = Collector::new(bounds);
        collector.ingest_acquisition(location(), b"{").unwrap();
        assert!(collector.ingest_acquisition(location(), b"{").is_err());
        assert!(collector.finish(0, 20).is_err());
        let mut collector = Collector::new(limits());
        let mut source = location();
        source.segment_name = "x".repeat(256);
        assert!(collector.ingest_acquisition(source, &bytes(&acquisition())).is_err());
        assert!(collector.finish(0, 20).is_err());
    }

    #[test]
    fn legacy_request_without_schema_is_unknown() {
        let mut value = request();
        value.as_object_mut().unwrap().remove("schema");
        let mut collector = Collector::new(limits());
        collector.ingest_request(location(), &bytes(&value)).unwrap();
        let report = collector.finish(0, 20).unwrap();
        assert!(!report.semantic_decode_complete);
        assert_eq!(report.diagnostics[0].code, "legacy_schema_unknown");
        assert!(report.groups.is_empty());
    }

    #[test]
    fn noncanonical_identity_hashes_are_rejected_not_misreported_as_conflict() {
        for field in ["invocation_id", "request_binding_sha256"] {
            for invalid in ["A".repeat(64), "short-id".into(), "g".repeat(64)] {
                let mut value = acquisition();
                value[field] = json!(invalid);
                diagnostic(&value, "malformed");
                let mut value = request();
                value[field] = json!(invalid);
                let mut collector = Collector::new(limits());
                collector.ingest_request(location(), &bytes(&value)).unwrap();
                let report = collector.finish(0, 20).unwrap();
                assert!(report.groups.is_empty());
                assert_eq!(report.diagnostics[0].code, "malformed");
            }
        }
    }

    #[test]
    fn binding_provider_and_model_mismatches_are_observed_conflicts() {
        for (field, different) in [
            ("request_binding_sha256", "b".repeat(64)),
            ("provider", "different-provider".into()),
            ("wire_model", "different-model".into()),
        ] {
            let mut value = acquisition();
            value[field] = json!(different);
            let mut collector = Collector::new(limits());
            collector.ingest_request(location(), &bytes(&request())).unwrap();
            collector.ingest_acquisition(location(), &bytes(&value)).unwrap();
            assert_eq!(collector.finish(0, 20).unwrap().groups[0].association, Association::Conflict);
        }
    }

    #[test]
    fn timestamp_only_divergence_explains_conflict_without_claiming_budget_discrepancy() {
        let mut later = acquisition();
        later["ts_unix"] = json!(11);
        let mut collector = Collector::new(limits());
        collector.ingest_acquisition(location(), &bytes(&acquisition())).unwrap();
        collector.ingest_acquisition(location(), &bytes(&later)).unwrap();
        let report = collector.finish(10, 10).unwrap();
        let group = &report.groups[0];
        assert_eq!(group.association, Association::Conflict);
        assert_eq!(group.difference_fields, ["acquisition.ts_unix"]);
        assert_eq!(group.acquisitions.len(), 2);
        assert!(!group.acquisitions[1].is_in_window);

        // Different request/acquisition times are expected lifecycle ordering.
        let mut collector = Collector::new(limits());
        collector.ingest_request(location(), &bytes(&request())).unwrap();
        collector.ingest_acquisition(location(), &bytes(&later)).unwrap();
        let report = collector.finish(10, 11).unwrap();
        assert_eq!(report.groups[0].association, Association::Matched);
        assert!(report.groups[0].difference_fields.is_empty());
    }
}
