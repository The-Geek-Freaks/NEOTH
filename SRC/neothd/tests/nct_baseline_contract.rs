use std::collections::BTreeMap;

use neothd::sub_agents::schema::{
    NCT_BASELINE_CANONICAL_CORPUS_VERSION, NCT_BASELINE_CONTENT_FREE_POLICY_V1,
    NCT_BASELINE_CORPUS_SCHEMA_V2, NCT_BASELINE_HOLDOUT_CASE_IDS,
    NCT_BASELINE_HOLDOUT_CORPUS_SHA256, NCT_BASELINE_HOLDOUT_FIXTURE_PATH,
    NCT_BASELINE_MEMBERSHIP_SHA256, NCT_BASELINE_MEMBERSHIP_VERSION, NCT_BASELINE_TRAIN_CASE_IDS,
    NCT_BASELINE_TRAIN_CORPUS_SHA256, NCT_BASELINE_TRAIN_FIXTURE_PATH, NctBaselineCorpus,
    NctCorpusId, NctFixtureSplit, NctQualityOutcome, NctRawContentPolicy, NctRouteIdentity,
    nct_baseline_coverage_report, parse_nct_baseline_fixture,
};

const TRAIN_FIXTURE: &[u8] = include_bytes!("fixtures/nct_baseline/nct_baseline_train_v2.json");
const HOLDOUT_FIXTURE: &[u8] = include_bytes!("fixtures/nct_baseline/nct_baseline_holdout_v2.json");

fn fixtures() -> (NctBaselineCorpus, NctBaselineCorpus) {
    let train = parse_nct_baseline_fixture(TRAIN_FIXTURE)
        .expect("train fixture must pass raw-content and strict NCT v2 validation");
    let holdout = parse_nct_baseline_fixture(HOLDOUT_FIXTURE)
        .expect("holdout fixture must pass raw-content and strict NCT v2 validation");
    (train, holdout)
}

fn fixture_value(raw: &[u8]) -> serde_json::Value {
    serde_json::from_slice(raw).expect("checked-in fixture is JSON")
}

fn fixture_bytes(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("mutated fixture serializes")
}

#[test]
fn nct_baseline_v2_is_content_free_and_has_strict_train_holdout_partitions() {
    let (train, holdout) = fixtures();

    assert_eq!(train.schema(), NCT_BASELINE_CORPUS_SCHEMA_V2);
    assert_eq!(holdout.schema(), NCT_BASELINE_CORPUS_SCHEMA_V2);
    assert_eq!(train.corpus_id(), NctCorpusId::TrainV2);
    assert_eq!(holdout.corpus_id(), NctCorpusId::HoldoutV2);
    assert_eq!(train.split(), NctFixtureSplit::Train);
    assert_eq!(holdout.split(), NctFixtureSplit::Holdout);
    assert_eq!(
        train.raw_content_policy(),
        NctRawContentPolicy::ContentFreeV1
    );
    assert_eq!(
        holdout.raw_content_policy(),
        NctRawContentPolicy::ContentFreeV1
    );
    assert_eq!(
        train.raw_content_policy().as_str(),
        NCT_BASELINE_CONTENT_FREE_POLICY_V1
    );

    let train_ids = train
        .cases()
        .iter()
        .map(|case| case.case_id())
        .collect::<std::collections::BTreeSet<_>>();
    let holdout_ids = holdout
        .cases()
        .iter()
        .map(|case| case.case_id())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(
        train_ids.is_disjoint(&holdout_ids),
        "no frozen case may cross from train into holdout"
    );

    for raw in [TRAIN_FIXTURE, HOLDOUT_FIXTURE] {
        for forbidden in [
            b"NCT_RAW_".as_slice(),
            b"sk-".as_slice(),
            b"Bearer ".as_slice(),
            b"-----BEGIN".as_slice(),
        ] {
            assert!(
                !raw.windows(forbidden.len())
                    .any(|window| window == forbidden),
                "raw baseline fixture must remain content-free"
            );
        }
    }
}

#[test]
fn nct_baseline_v2_emits_a_deterministic_complete_coverage_report() {
    let (train, holdout) = fixtures();
    let report = nct_baseline_coverage_report(&train, &holdout)
        .expect("checked fixture paths, schemas, partitions, and route coverage");

    assert_eq!(report.schema, NCT_BASELINE_CORPUS_SCHEMA_V2);
    assert_eq!(report.membership_version, NCT_BASELINE_MEMBERSHIP_VERSION);
    assert_eq!(report.membership_sha256, NCT_BASELINE_MEMBERSHIP_SHA256);
    assert_eq!(
        report.canonical_corpus_version,
        NCT_BASELINE_CANONICAL_CORPUS_VERSION
    );
    assert_eq!(report.train_corpus_sha256, NCT_BASELINE_TRAIN_CORPUS_SHA256);
    assert_eq!(
        report.holdout_corpus_sha256,
        NCT_BASELINE_HOLDOUT_CORPUS_SHA256
    );
    assert_eq!(report.train_fixture_path, NCT_BASELINE_TRAIN_FIXTURE_PATH);
    assert_eq!(
        report.holdout_fixture_path,
        NCT_BASELINE_HOLDOUT_FIXTURE_PATH
    );
    assert_eq!(report.train_case_count, 4);
    assert_eq!(report.holdout_case_count, 4);
    assert_eq!(
        report.route_case_counts,
        BTreeMap::from([
            ("cluster_worker".to_string(), 1),
            ("council".to_string(), 1),
            ("direct".to_string(), 1),
            ("fallback".to_string(), 1),
            ("nexus".to_string(), 1),
            ("retry".to_string(), 1),
            ("streaming".to_string(), 1),
            ("sub_agent".to_string(), 1),
        ])
    );
    assert_eq!(
        NctRouteIdentity::ALL.map(NctRouteIdentity::as_str),
        [
            "direct",
            "nexus",
            "council",
            "retry",
            "fallback",
            "streaming",
            "sub_agent",
            "cluster_worker",
        ]
    );

    let mut schema_drift = fixture_value(TRAIN_FIXTURE);
    schema_drift["schema"] = serde_json::json!("neoth.nct-baseline-corpus.v3");
    assert!(
        parse_nct_baseline_fixture(&fixture_bytes(&schema_drift))
            .unwrap_err()
            .contains("unsupported NCT corpus schema")
    );

    let mut route_drift = fixture_value(HOLDOUT_FIXTURE);
    route_drift["cases"][3]["route"] = serde_json::json!("direct");
    assert_eq!(
        parse_nct_baseline_fixture(&fixture_bytes(&route_drift)).unwrap_err(),
        "NCT canonical corpus digest drifted"
    );

    let mut split_drift = fixture_value(HOLDOUT_FIXTURE);
    split_drift["split"] = serde_json::json!("train");
    assert!(
        parse_nct_baseline_fixture(&fixture_bytes(&split_drift))
            .unwrap_err()
            .contains("split mismatch")
    );
}

#[test]
fn nct_baseline_v2_rejects_raw_content_before_typed_deserialization() {
    let malformed_with_secret = br#"not-json-with-sk-NCT-SYNTHETIC-SENTINEL"#;
    let error = parse_nct_baseline_fixture(malformed_with_secret).unwrap_err();
    assert_eq!(
        error, "NCT fixture contains a forbidden raw-content fragment",
        "raw scanning must run before JSON or typed deserialization"
    );

    let escaped_secret = br#"{"unreviewed":"sk\u002dNCT-SYNTHETIC-SENTINEL"}"#;
    let error = parse_nct_baseline_fixture(escaped_secret).unwrap_err();
    assert_eq!(
        error, "NCT fixture contains a forbidden raw-content fragment",
        "lossless Value scanning must catch equivalent escaped encodings"
    );

    assert!(TRAIN_FIXTURE.starts_with(b"{\n"));
    let mut duplicate_key = b"{\n  \"schema\": \"shadowed synthetic diary material\",\n".to_vec();
    duplicate_key.extend_from_slice(&TRAIN_FIXTURE[2..]);
    let error = parse_nct_baseline_fixture(&duplicate_key).unwrap_err();
    assert_eq!(error, "invalid NCT fixture JSON: duplicate object key");
    assert!(!error.contains("shadowed synthetic diary material"));

    let mut forbidden_field = fixture_value(TRAIN_FIXTURE);
    forbidden_field["cases"][0]["prompt_baseline"]["shape"]["raw_prompt"] =
        serde_json::json!("synthetic-value-that-must-not-be-echoed");
    let error = parse_nct_baseline_fixture(&fixture_bytes(&forbidden_field)).unwrap_err();
    assert!(error.contains("forbidden content-bearing field: raw_prompt"));
    assert!(!error.contains("synthetic-value-that-must-not-be-echoed"));
}

#[test]
fn nct_baseline_v2_rejects_unknown_fields_at_every_nested_boundary() {
    let mut root_unknown = fixture_value(TRAIN_FIXTURE);
    root_unknown["unreviewed_root_field"] = serde_json::json!(1);
    assert!(
        parse_nct_baseline_fixture(&fixture_bytes(&root_unknown))
            .unwrap_err()
            .contains("unknown field")
    );

    let mut baseline_unknown = fixture_value(TRAIN_FIXTURE);
    baseline_unknown["cases"][0]["prompt_baseline"]["unreviewed_metric"] = serde_json::json!(1);
    assert!(
        parse_nct_baseline_fixture(&fixture_bytes(&baseline_unknown))
            .unwrap_err()
            .contains("unknown field")
    );

    let mut shape_unknown = fixture_value(TRAIN_FIXTURE);
    shape_unknown["cases"][0]["prompt_baseline"]["shape"]["unreviewed_bytes"] =
        serde_json::json!(1);
    assert!(
        parse_nct_baseline_fixture(&fixture_bytes(&shape_unknown))
            .unwrap_err()
            .contains("unknown field")
    );

    let mut outcome_unknown = fixture_value(TRAIN_FIXTURE);
    outcome_unknown["cases"][0]["outcome"]["unreviewed_outcome"] = serde_json::json!(1);
    assert!(
        parse_nct_baseline_fixture(&fixture_bytes(&outcome_unknown))
            .unwrap_err()
            .contains("unknown field")
    );
}

#[test]
fn nct_baseline_v2_freezes_corpus_identity_and_exact_split_membership() {
    let (train, holdout) = fixtures();
    assert_eq!(
        train
            .cases()
            .iter()
            .map(|case| case.case_id())
            .collect::<Vec<_>>(),
        NCT_BASELINE_TRAIN_CASE_IDS
    );
    assert_eq!(
        holdout
            .cases()
            .iter()
            .map(|case| case.case_id())
            .collect::<Vec<_>>(),
        NCT_BASELINE_HOLDOUT_CASE_IDS
    );

    let mut cross_split = fixture_value(TRAIN_FIXTURE);
    cross_split["cases"][0]["case_id"] = serde_json::json!(NCT_BASELINE_HOLDOUT_CASE_IDS[0]);
    assert!(
        parse_nct_baseline_fixture(&fixture_bytes(&cross_split))
            .unwrap_err()
            .contains("wrong split prefix")
    );

    let mut cross_split_corpus = fixture_value(TRAIN_FIXTURE);
    cross_split_corpus["corpus_id"] = serde_json::json!("nct-baseline-holdout-v2");
    assert!(
        parse_nct_baseline_fixture(&fixture_bytes(&cross_split_corpus))
            .unwrap_err()
            .contains("split mismatch")
    );

    let mut prefix_valid_but_unreviewed = fixture_value(TRAIN_FIXTURE);
    prefix_valid_but_unreviewed["cases"][0]["case_id"] =
        serde_json::json!("nct-train-unreviewed-pass");
    assert!(
        parse_nct_baseline_fixture(&fixture_bytes(&prefix_valid_but_unreviewed))
            .unwrap_err()
            .contains("membership differs from the reviewed manifest")
    );

    let mut reordered = fixture_value(HOLDOUT_FIXTURE);
    reordered["cases"]
        .as_array_mut()
        .expect("cases array")
        .swap(0, 1);
    assert!(
        parse_nct_baseline_fixture(&fixture_bytes(&reordered))
            .unwrap_err()
            .contains("membership differs from the reviewed manifest")
    );

    let mut arbitrary_corpus_id = fixture_value(TRAIN_FIXTURE);
    arbitrary_corpus_id["corpus_id"] = serde_json::json!("x".repeat(200));
    assert!(
        parse_nct_baseline_fixture(&fixture_bytes(&arbitrary_corpus_id))
            .unwrap_err()
            .contains("outside a closed set")
    );

    let mut open_policy = fixture_value(TRAIN_FIXTURE);
    open_policy["raw_content_policy"] = serde_json::json!("allow_synthetic_text");
    assert!(
        parse_nct_baseline_fixture(&fixture_bytes(&open_policy))
            .unwrap_err()
            .contains("outside a closed set")
    );
}

#[test]
fn nct_baseline_v2_pins_measurements_and_outcomes_not_only_case_ids() {
    let mut changed_latency = fixture_value(TRAIN_FIXTURE);
    changed_latency["cases"][0]["prompt_baseline"]["completion_latency_ms"] = serde_json::json!(49);
    assert_eq!(
        parse_nct_baseline_fixture(&fixture_bytes(&changed_latency)).unwrap_err(),
        "NCT canonical corpus digest drifted"
    );

    let mut changed_failure = fixture_value(TRAIN_FIXTURE);
    changed_failure["cases"][3]["outcome"]["failure"] = serde_json::json!("provider");
    assert_eq!(
        parse_nct_baseline_fixture(&fixture_bytes(&changed_failure)).unwrap_err(),
        "NCT canonical corpus digest drifted"
    );
}

#[test]
fn nct_baseline_v2_keeps_shape_usage_latency_cost_repair_and_failure_boundaries() {
    let (train, holdout) = fixtures();
    let cases = train
        .cases()
        .iter()
        .chain(holdout.cases())
        .collect::<Vec<_>>();

    let direct = cases
        .iter()
        .find(|case| case.route() == NctRouteIdentity::Direct)
        .expect("direct coverage");
    assert_eq!(direct.prompt_baseline().shape().context_bytes(), 96);
    assert_eq!(direct.prompt_baseline().shape().repeated_segment_bytes(), 0);
    assert_eq!(direct.prompt_baseline().input_tokens(), Some(104));
    assert_eq!(direct.prompt_baseline().completion_latency_ms(), 48);
    assert_eq!(direct.outcome().total_cost_microunits(), 1200);

    let nexus = cases
        .iter()
        .find(|case| case.route() == NctRouteIdentity::Nexus)
        .expect("nexus coverage");
    assert_eq!(nexus.prompt_baseline().input_tokens(), None);
    assert_eq!(nexus.prompt_baseline().output_tokens(), None);

    let retry = cases
        .iter()
        .find(|case| case.route() == NctRouteIdentity::Retry)
        .expect("retry coverage");
    assert_eq!(
        retry.prompt_baseline().shape().repeated_segment_bytes(),
        290
    );
    assert_eq!(retry.outcome().repair_attempts(), 1);
    assert_eq!(retry.outcome().quality(), NctQualityOutcome::Fail);
    assert!(retry.outcome().failure().is_some());

    let streaming = cases
        .iter()
        .find(|case| case.route() == NctRouteIdentity::Streaming)
        .expect("streaming coverage");
    assert_eq!(streaming.prompt_baseline().cache_creation_tokens(), Some(0));
    assert_eq!(streaming.prompt_baseline().cache_read_tokens(), Some(24));
    assert_eq!(streaming.prompt_baseline().completion_latency_ms(), 19);

    assert_eq!(
        cases
            .iter()
            .map(|case| case.outcome().total_cost_microunits())
            .sum::<u64>(),
        14_600
    );
}
