use super::*;
use clap::Parser;
use serde_json::{Value, json};
use crate::daemon::usage_log::{
    UsageEvent, terminal_usage_snapshot, terminal_usage_snapshot_v2, terminal_usage_snapshot_v3,
};
use crate::providers::cost::PriceRow;
use crate::providers::pricing_basis::{AuthorizationPriceBound, PricingBasis};

fn limits() -> Limits {
    Limits { max_records: 100, max_diagnostics: 10, max_input_bytes: 100_000 }
}
fn loc(offset: u64) -> Location {
    Location { segment_name: "000001.wal".into(), segment_generation: 1, segment_seq: 1,
        segment_start_ts_ns: 0, segment_node_id: [0; 16], logical_offset: offset }
}
fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}
fn request() -> Value {
    json!({"schema":"neoth.provider-lifecycle.v1", "invocation_id":"a".repeat(64),
        "request_binding_sha256":"b".repeat(64), "provider":"openai_api",
        "wire_model":"gpt-4o", "ts_unix":10, "private_extra":"never-echo-this-prompt"})
}
fn plan() -> Value {
    json!({"invocation_id":"a".repeat(64), "authorization_id":"a".repeat(64),
        "authorization_binding":"actual_leaf_request", "request_binding_sha256":"b".repeat(64),
        "provider":"openai_api", "model":"gpt-4o", "ts_unix":20,
        "input_bound_kind":"utf8_bytes_plus_request_message_overhead",
        "input_token_upper_bound":200, "output_token_ceiling":100,
        "authorization_price_bound":null, "cost_bound_kind":"token_bounded_unknown_pricing"})
}
fn acquisition() -> Value {
    json!({"schema":"neoth.provider-budget-acquired.v1", "invocation_id":"a".repeat(64),
        "request_binding_sha256":"b".repeat(64), "provider":"openai_api", "wire_model":"gpt-4o",
        "ts_unix":30, "daily_reserved_usd_nanos":0, "operation":null, "cluster":null})
}
fn terminal(version: u8) -> Value {
    let mut event = UsageEvent {
        ts_unix: 40, provider: "openai_api".into(), model: "gpt-4o".into(),
        input_tokens: Some(100), output_tokens: Some(50), latency_ms: 7, ok: true,
        cache_creation_tokens: Some(0), cache_read_tokens: None, automated: false,
        invocation_id: Some("a".repeat(64)), outcome: Some("complete".into()),
        call_scope: Some("test.provenance".into()),
        cost_usd: Some(1.2345678901234567), cache_savings_usd: Some(-0.25),
        ..Default::default()
    };
    if version >= 4 {
        event.pricing_basis = Some(PricingBasis::from_price(&event.provider, &event.model,
            PriceRow { input_eur_per_mtok: 7.25, output_eur_per_mtok: 13.5 }));
    }
    if version == 5 {
        let item = crate::tokens::budget::BlockItem::new(crate::tokens::budget::Block::E, "user")
            .with_prompt_origin(crate::tokens::prompt_attribution::PromptOrigin::User);
        event.prompt_tax = Some(crate::tokens::budget::PromptTax {
            components: Some(crate::tokens::prompt_attribution::PromptAttribution::from_retained_items(
                &[item], 520).unwrap()),
            ..Default::default()
        });
    }
    let mut value = json!({"schema":"neoth.provider-lifecycle.v1",
        "usage_projection_schema":format!("neoth.provider-usage.v{version}"),
        "invocation_id":event.invocation_id, "request_binding_sha256":"b".repeat(64),
        "provider":event.provider, "wire_model":event.model, "model":event.model,
        "ts_unix":event.ts_unix, "ok":event.ok, "terminal_kind":event.outcome,
        "latency_ms":event.latency_ms, "input_tokens":event.input_tokens, "output_tokens":event.output_tokens,
        "cache_creation_tokens":event.cache_creation_tokens, "cache_read_tokens":event.cache_read_tokens,
        "automated":event.automated, "call_scope":event.call_scope, "source":event.source,
        "call_type":event.call_type, "streaming":event.streaming, "prompt_tax":event.prompt_tax});
    if version >= 4 {
        value["pricing_basis"] = serde_json::to_value(&event.pricing_basis).unwrap();
    }
    if version >= 3 {
        value["usage_snapshot"] = match version {
            3 => terminal_usage_snapshot(&event).unwrap(),
            4 => terminal_usage_snapshot_v2(&event).unwrap(),
            _ => terminal_usage_snapshot_v3(&event).unwrap(),
        };
    }
    value
}
fn records() -> Vec<(u8, u8, Value)> {
    vec![(EVENT_TYPE_PROVIDER_REQUEST, 0, request()), (EVENT_TYPE_COST_ESTIMATE_SHOWN, 0, plan()),
        (EVENT_TYPE_EXTENDED, ExtendedSubtype::ProviderBudgetAcquired as u8, acquisition()),
        (EVENT_TYPE_PROVIDER_RESPONSE, 0, terminal(2))]
}
fn feed(c: &mut Collector, rows: &[(u8, u8, Value)]) -> Result<()> {
    for (offset, (kind, subtype, value)) in rows.iter().enumerate() {
        c.ingest(*kind, *subtype, loc(offset as u64), &bytes(value))?;
    }
    Ok(())
}
fn collect(rows: &[(u8, u8, Value)]) -> Observations {
    let mut c = Collector::new(limits());
    feed(&mut c, rows).unwrap();
    c.finish(0, 100).unwrap()
}

#[test]
fn provenance_correlates_four_kinds_without_repricing_legacy_or_inventing_scope() {
    let report = collect(&records());
    assert!(report.semantic_decode_complete);
    let g = &report.groups[0];
    assert_eq!(g.association, Association::ObservedMetadataMatch);
    assert!(g.plans[0].record.bound.is_none());
    assert_eq!(g.acquisitions[0].record.daily_reserved_usd_nanos, Some(0));
    assert!(g.acquisitions[0].record.operation.is_none());
    let t = &g.terminals[0].record;
    assert_eq!(t.event.input_tokens, Some(100));
    assert_eq!(t.event.cost_usd, None);
    assert_eq!(t.cost_usd_bits, None);
    assert_eq!(t.amount_provenance, "legacy_unpriced");
}

#[test]
fn provenance_compares_all_identities_without_normalizing_provider_aliases() {
    let mut alias_rows = records();
    alias_rows[0].2["model"] = json!("other-model");
    let alias_report = collect(&alias_rows);
    assert!(!alias_report.semantic_decode_complete);
    assert_eq!(alias_report.groups[0].missing_kinds, ["request"]);
    assert_eq!(alias_report.diagnostics[0].code, "malformed");
    for (field, value, difference) in [
        ("request_binding_sha256", json!("c".repeat(64)), "request_binding_sha256"),
        ("provider", json!("OpenAI"), "provider"),
        ("model", json!("other-model"), "wire_model"),
    ] {
        let mut rows = records();
        rows[1].2[field] = value;
        let report = collect(&rows);
        let g = &report.groups[0];
        assert_eq!(g.association, Association::Conflict);
        assert!(g.difference_fields.contains(difference));
        assert_eq!((g.requests.len(), g.plans.len(), g.acquisitions.len(), g.terminals.len()), (1,1,1,1));
    }
}

#[test]
fn provenance_retains_duplicates_and_prioritizes_conflicts_over_duplicate_status() {
    for (index, changed) in [(0, false), (1, false), (2, false), (3, false), (0, true), (1, true), (2, true), (3, true)] {
        let mut rows = records();
        let mut duplicate = rows[index].clone();
        if changed {
            duplicate.2["ts_unix"] = json!(99);
        }
        rows.push(duplicate);
        let report = collect(&rows);
        let g = &report.groups[0];
        assert_eq!(g.association, if changed { Association::Conflict } else { Association::Duplicate });
        assert_eq!(g.duplicate_kinds.len(), 1);
        assert_eq!(g.requests.len()+g.plans.len()+g.acquisitions.len()+g.terminals.len(), 5);
    }
}

#[test]
fn provenance_missing_binding_or_lifecycle_never_matches_by_invocation_alone() {
    for missing in ["request_binding_sha256", "schema"] {
        let mut rows = records();
        rows[3].2.as_object_mut().unwrap().remove(missing);
        let report = collect(&rows);
        let g = &report.groups[0];
        assert_eq!(g.association, Association::Unbound);
        assert!(g.unbound_terminal_present);
        assert_eq!(g.terminals[0].record.binding.is_some(), missing == "schema");
    }
    let mut rows = records();
    rows.remove(2);
    let report = collect(&rows);
    assert_eq!(report.groups[0].association, Association::Incomplete);
    assert_eq!(report.groups[0].missing_kinds, ["acquisition"]);
}

#[test]
fn provenance_union_window_keeps_all_kinds_and_labels_outside_context() {
    for time in [10, 20, 30, 40] {
        let mut c = Collector::new(limits());
        feed(&mut c, &records()).unwrap();
        let report = c.finish(time, time).unwrap();
        let g = &report.groups[0];
        assert_eq!(g.association, Association::ObservedMetadataMatch);
        assert_eq!([g.requests[0].is_in_window, g.plans[0].is_in_window,
            g.acquisitions[0].is_in_window, g.terminals[0].is_in_window],
            [time == 10, time == 20, time == 30, time == 40]);
    }
    let mut c = Collector::new(limits());
    feed(&mut c, &records()).unwrap();
    assert!(c.finish(41, 50).unwrap().groups.is_empty());
}

#[test]
fn provenance_plan_rejects_identity_and_price_contract_drift() {
    for (field, value) in [
        ("authorization_id", json!("c".repeat(64))), ("authorization_binding", json!("preflight")),
        ("output_token_ceiling", json!(0)), ("input_bound_kind", json!("model_tokenizer")),
        ("cost_bound_kind", json!("wire_token_bounded_reviewed_price_estimate")),
    ] {
        let mut payload = plan();
        payload[field] = value;
        assert!(decode::plan(&bytes(&payload)).is_err(), "{field}");
    }
    for field in ["authorization_price_bound", "output_token_ceiling"] {
        let mut payload = plan();
        payload.as_object_mut().unwrap().remove(field);
        assert!(decode::plan(&bytes(&payload)).is_err());
    }
    let mut payload = plan();
    payload["output_token_ceiling"] = Value::Null;
    payload["cost_bound_kind"] = json!("unbounded_provider_invocation");
    assert!(decode::plan(&bytes(&payload)).unwrap().bound.is_none());
}

#[test]
fn provenance_plan_validates_frozen_rate_bits_and_preserves_zero_bound() {
    for rate in [0.0, 7.25] {
        let mut payload = plan();
        let bound = AuthorizationPriceBound::from_price("openai_api", "gpt-4o",
            PriceRow { input_eur_per_mtok: rate, output_eur_per_mtok: rate }, 200, 100, false);
        payload["authorization_price_bound"] = serde_json::to_value(&bound).unwrap();
        payload["cost_bound_kind"] = json!("wire_token_bounded_reviewed_price_estimate");
        assert_eq!(decode::plan(&bytes(&payload)).unwrap().bound, Some(bound));
        payload["input_token_upper_bound"] = json!(201);
        assert!(decode::plan(&bytes(&payload)).is_err());
        payload["input_token_upper_bound"] = json!(200);
        payload["authorization_price_bound"]["bound_usd_bits"] = json!("7ff8000000000000");
        assert!(decode::plan(&bytes(&payload)).is_err());
    }
}

#[test]
fn provenance_terminal_retains_each_frozen_schema_and_prompt_components() {
    for version in [3, 4, 5] {
        let payload = terminal(version);
        let decoded = decode::terminal(EVENT_TYPE_PROVIDER_RESPONSE, &bytes(&payload)).unwrap();
        assert_eq!(decoded.cost_usd_bits, Some(format!("{:016x}", 1.2345678901234567_f64.to_bits())));
        assert_eq!(decoded.cache_savings_usd_bits, Some(format!("{:016x}", (-0.25_f64).to_bits())));
        assert_eq!(decoded.event.pricing_basis.is_some(), version >= 4);
        assert_eq!(decoded.event.prompt_tax.and_then(|v| v.components).is_some(), version == 5);
        let mut corrupted = payload;
        corrupted["input_tokens"] = json!(101);
        assert!(decode::terminal(EVENT_TYPE_PROVIDER_RESPONSE, &bytes(&corrupted)).is_err());
    }
}

#[test]
fn provenance_terminal_unknown_zero_alias_and_frame_kind_remain_distinct() {
    let mut payload = terminal(2);
    payload["input_tokens"] = Value::Null;
    payload["output_tokens"] = json!(0);
    let decoded = decode::terminal(EVENT_TYPE_PROVIDER_RESPONSE, &bytes(&payload)).unwrap();
    assert_eq!(decoded.event.input_tokens, None);
    assert_eq!(decoded.event.output_tokens, Some(0));
    assert!(decode::terminal(EVENT_TYPE_PROVIDER_ERROR, &bytes(&payload)).is_err());
    payload["model"] = json!("alias");
    assert!(decode::terminal(EVENT_TYPE_PROVIDER_RESPONSE, &bytes(&payload)).is_err());
    for bad in [Value::Null, json!(77), json!("neoth.provider-usage.v99")] {
        let mut payload = terminal(2);
        payload["usage_projection_schema"] = bad;
        assert!(decode::terminal(EVENT_TYPE_PROVIDER_RESPONSE, &bytes(&payload)).is_err());
    }
}

#[test]
fn provenance_response_and_error_are_alternative_terminal_occurrences() {
    let mut rows = records();
    let mut error = terminal(2);
    error["ok"] = json!(false);
    error["error_kind"] = json!("transport");
    error.as_object_mut().unwrap().remove("terminal_kind");
    rows[3] = (EVENT_TYPE_PROVIDER_ERROR, 0, error);
    assert_eq!(collect(&rows).groups[0].association, Association::ObservedMetadataMatch);
    rows.push((EVENT_TYPE_PROVIDER_RESPONSE, 0, terminal(2)));
    let report = collect(&rows);
    assert_eq!(report.groups[0].association, Association::Conflict);
    assert_eq!(report.groups[0].terminals.len(), 2);
}

#[test]
fn provenance_rejects_recursive_duplicate_keys_without_echoing_payloads() {
    for (kind, subtype, payload) in records() {
        for extra in [r#""hidden":{"secret":"never-echo","secret":"never-echo"}"#,
            r#""hidden":[{"secret":1,"secret":2}]"#] {
            let text = serde_json::to_string(&payload).unwrap();
            let raw = format!("{{{extra},{}", &text[1..]);
            let mut c = Collector::new(limits());
            c.ingest(kind, subtype, loc(1), raw.as_bytes()).unwrap();
            let report = c.finish(0, 100).unwrap();
            assert!(report.groups.is_empty());
            assert!(!report.semantic_decode_complete);
            assert_eq!(report.diagnostics[0].code, "malformed");
            assert!(!serde_json::to_string(&report).unwrap().contains("never-echo"));
        }
    }
    assert!(unique_json::parse_unique_json(b"{} {}").is_err());
}

#[test]
fn provenance_shares_record_byte_and_diagnostic_limits_across_all_kinds() {
    let rows = records();
    let mut c = Collector::new(Limits { max_records: 4, ..limits() });
    feed(&mut c, &rows).unwrap();
    assert!(c.ingest(EVENT_TYPE_PROVIDER_REQUEST, 0, loc(9), &bytes(&request())).is_err());
    assert!(c.finish(0, 100).is_err());
    let max_input_bytes = rows.iter().map(|(_,_,v)| bytes(v).len() + loc(0).segment_name.len()).sum();
    let mut c = Collector::new(Limits { max_input_bytes, ..limits() });
    feed(&mut c, &rows).unwrap();
    assert!(c.ingest(EVENT_TYPE_COST_ESTIMATE_SHOWN, 0, loc(9), &bytes(&plan())).is_err());
    assert!(c.finish(0, 100).is_err());
    let mut c = Collector::new(Limits { max_diagnostics: 1, ..limits() });
    c.ingest(EVENT_TYPE_PROVIDER_RESPONSE, 0, loc(1), b"bad").unwrap();
    assert!(c.ingest(EVENT_TYPE_PROVIDER_REQUEST, 0, loc(2), b"bad").is_err());
    assert!(c.finish(0, 100).is_err());
}

#[test]
fn provenance_ignores_unrelated_event_types_and_discards_late_scan_failures() {
    let mut c = Collector::new(Limits { max_records: 0, ..limits() });
    c.ingest(EVENT_TYPE_EXTENDED, 0, loc(0), &bytes(&acquisition())).unwrap();
    assert!(c.finish(0, 100).unwrap().groups.is_empty());
    let failed = collect_after_scan(0, 100, |c| {
        feed(c, &records())?;
        bail!("later authentication failure")
    });
    assert!(failed.is_err());
}

#[test]
fn provenance_incomplete_prefix_and_diagnostics_limit_observed_matches() {
    let inspection = collect_after_scan(0, 100, |c| {
        feed(c, &records())?;
        c.ingest(EVENT_TYPE_COST_ESTIMATE_SHOWN, 0, loc(99), b"{}")?;
        Ok(AuthenticatedPrefixScan { complete: false, boundaries: vec![] })
    }).unwrap();
    assert!(!inspection.scan.complete);
    assert!(!inspection.observations.semantic_decode_complete);
    assert!(!inspection.full_history_complete);
    assert!(!inspection.atomic_latest_snapshot);
    assert_eq!(inspection.observations.groups[0].association, Association::ObservedMetadataMatch);
    let text = render(&inspection, UsageFormat::Json).unwrap();
    assert!(!text.contains("never-echo-this-prompt"));
    assert_eq!(inspection.observations.diagnostics[0].code, "legacy_plan_unavailable");
}

#[derive(Parser)]
struct TestCli {
    #[command(flatten)]
    args: UsageArgs,
}

#[test]
fn provenance_cli_conflicts_leave_legacy_and_acquisitions_modes_available() {
    assert!(!TestCli::try_parse_from(["test"]).unwrap().args.provenance);
    assert!(TestCli::try_parse_from(["test", "--acquisitions"]).unwrap().args.acquisitions);
    assert!(TestCli::try_parse_from(["test", "--provenance"]).unwrap().args.provenance);
    assert!(TestCli::try_parse_from(["test", "--provenance", "--acquisitions"]).is_err());
    assert!(TestCli::try_parse_from(["test", "--provenance", "--currency", "EUR"]).is_err());
    let home = tempfile::tempdir().unwrap();
    let args = TestCli::try_parse_from(["test", "--provenance", "--format", "invalid"]).unwrap().args;
    assert!(run(home.path(), args).is_err());
    assert!(std::fs::read_dir(home.path()).unwrap().next().is_none());
}

#[test]
fn provenance_missing_home_stays_unknown_and_table_escapes_recorded_strings() {
    let home = tempfile::tempdir().unwrap();
    let empty = inspect(home.path(), 0, 100).unwrap();
    assert!(empty.scan.boundaries.is_empty());
    assert!(!empty.full_history_complete);
    assert!(std::fs::read_dir(home.path()).unwrap().next().is_none());
    let inspection = collect_after_scan(0, 100, |c| {
        let mut payload = request();
        payload["provider"] = json!("p\u{1b}[2J\nspoof");
        c.ingest(EVENT_TYPE_PROVIDER_REQUEST, 0, loc(1), &bytes(&payload))?;
        Ok(AuthenticatedPrefixScan { complete: true, boundaries: vec![] })
    }).unwrap();
    let text = render(&inspection, UsageFormat::Table).unwrap();
    assert!(!text.contains('\u{1b}'));
    assert!(!text.contains("\nspoof"));
    assert!(text.contains("\\u001b"));
}

fn snapshot(home: &Path) -> BTreeMap<std::path::PathBuf, Vec<u8>> {
    fn collect(root: &Path, path: &Path, files: &mut BTreeMap<std::path::PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(root, &path, files);
            } else {
                files.insert(path.strip_prefix(root).unwrap().to_path_buf(), std::fs::read(path).unwrap());
            }
        }
    }
    let mut files = BTreeMap::new();
    collect(home, home, &mut files);
    files
}

#[tokio::test]
async fn provenance_real_authenticated_wal_is_readonly_and_rejects_changed_key() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("wal")).unwrap();
    let (writer, join) = crate::wal::writer::spawn_for_home(
        home.path().join("wal/000001.wal"), home.path().to_path_buf()).unwrap();
    let mut rows = records();
    rows[3].2 = terminal(5);
    for (kind, subtype, value) in rows {
        let payload = bytes(&value);
        writer.append_authenticated(
            crate::wal::HeaderBuilder::new(kind, &payload).event_subtype(subtype).build(),
            payload).await.unwrap();
    }
    drop(writer);
    tokio::time::timeout(std::time::Duration::from_secs(5), join).await.unwrap().unwrap();
    std::fs::create_dir_all(home.path().join("usage")).unwrap();
    std::fs::write(home.path().join("usage/sentinel.jsonl"), b"not a usage projection\n").unwrap();
    let before = snapshot(home.path());
    let inspection = inspect(home.path(), 40, 40).unwrap();
    assert_eq!(inspection.observations.groups[0].association, Association::ObservedMetadataMatch);
    assert!(inspection.observations.groups[0].terminals[0].record.event.prompt_tax
        .as_ref().unwrap().components.is_some());
    assert_eq!(snapshot(home.path()), before);
    std::fs::write(home.path().join("wal/hmac.key"), [0x19u8; 32]).unwrap();
    assert!(inspect(home.path(), 0, 100).is_err());
}