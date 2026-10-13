#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use serde_json::Value as Json;
    use std::collections::BTreeMap;

    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct StrictConfig { enabled: bool, label: String }
    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
    struct Defaults {
        #[serde(default)] retries: u16,
        #[serde(default)] note: Option<String>,
    }
    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
    enum Tagged { Alarm { message: String }, Pause }
    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
    struct Service { mode: String, retries: u16 }
    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
    struct MergeDoc { defaults: Service, server: Service }
    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
    struct Recipe { name: String, steps: Vec<Step>, labels: BTreeMap<String, String>, enabled: bool }
    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
    enum Step { Shell { command: String }, Http { url: String } }

    #[test]
    fn dynamic_mapping_mutation_preserves_unknown_nested_blocks() {
        let src = "operator_id: alice\nplugins:\n  future:\n    enabled: true\n    endpoints: [one, two]\nchannels:\n  web:\n    retries: 3\n";
        let mut legacy: serde_yaml_legacy::Value = serde_yaml_legacy::from_str(src).unwrap();
        let mut candidate: serde_yaml_candidate::Value = serde_yaml_candidate::from_str(src).unwrap();
        legacy.as_mapping_mut().unwrap().insert(
            serde_yaml_legacy::Value::String("profile".into()),
            serde_yaml_legacy::Value::String("local".into()),
        );
        candidate.as_mapping_mut().unwrap().insert(
            serde_yaml_candidate::Value::String("profile".into()),
            serde_yaml_candidate::Value::String("local".into()),
        );
        let legacy_text = serde_yaml_legacy::to_string(&legacy).unwrap();
        let candidate_text = serde_yaml_candidate::to_string(&candidate).unwrap();
        let legacy_json: Json = serde_yaml_legacy::from_str(&legacy_text).unwrap();
        let candidate_json: Json = serde_yaml_candidate::from_str(&candidate_text).unwrap();
        let expected = serde_json::json!({"operator_id":"alice","profile":"local","plugins":{"future":{"enabled":true,"endpoints":["one","two"]}},"channels":{"web":{"retries":3}}});
        assert_eq!(legacy_json, expected);
        assert_eq!(candidate_json, expected);
    }

    fn typed_acceptance(src: &str) -> (bool, bool) {
        let legacy: serde_yaml_legacy::Value = serde_yaml_legacy::from_str(src).unwrap();
        let candidate: serde_yaml_candidate::Value = serde_yaml_candidate::from_str(src).unwrap();
        (serde_yaml_legacy::from_value::<StrictConfig>(legacy).is_ok(),
         serde_yaml_candidate::from_value::<StrictConfig>(candidate).is_ok())
    }

    #[test]
    fn from_value_rejects_wrong_field_type() {
        assert_eq!(typed_acceptance("enabled: definitely-not-a-bool\nlabel: primary\n"), (false, false));
        assert_eq!(typed_acceptance("enabled: true\nlabel: primary\n"), (true, true));
    }

    #[test]
    fn from_value_rejects_unknown_field_under_strict_schema() {
        assert_eq!(typed_acceptance("enabled: true\nlabel: primary\nfuture_only: preserve-me\n"), (false, false));
    }

    #[test]
    fn null_and_absent_defaults_match() {
        for src in ["{}", "retries: 7\nnote: null\n"] {
            let legacy: Defaults = serde_yaml_legacy::from_str(src).unwrap();
            let candidate: Defaults = serde_yaml_candidate::from_str(src).unwrap();
            assert_eq!(legacy, candidate, "{src}");
        }
    }

    #[test]
    fn tagged_enum_values_match() {
        let src = "!Alarm\nmessage: maintenance\n";
        let legacy: Tagged = serde_yaml_legacy::from_str(src).unwrap();
        let candidate: Tagged = serde_yaml_candidate::from_str(src).unwrap();
        assert_eq!(legacy, Tagged::Alarm { message: "maintenance".into() });
        assert_eq!(candidate, legacy);
    }

    #[test]
    fn legacy_scalar_resolution_is_compared() {
        let src = "yes: ON\nno: NO\noctalish: 012\n";
        let legacy: Json = serde_yaml_legacy::from_str(src).unwrap();
        let candidate: Json = serde_yaml_candidate::from_str(src).unwrap();
        assert_eq!(legacy, candidate);
    }

    #[test]
    fn anchors_and_explicit_merge_preserve_overrides() {
        let src = "defaults: &defaults\n  mode: safe\n  retries: 2\nserver:\n  <<: *defaults\n  retries: 5\n";
        let direct_legacy = serde_yaml_legacy::from_str::<MergeDoc>(src);
        let direct_candidate = serde_yaml_candidate::from_str::<MergeDoc>(src);
        assert_eq!(direct_legacy.is_ok(), direct_candidate.is_ok());
        if let (Ok(legacy), Ok(candidate)) = (direct_legacy, direct_candidate) {
            assert_eq!(legacy, candidate);
        }
        let mut legacy_value: serde_yaml_legacy::Value = serde_yaml_legacy::from_str(src).unwrap();
        let mut candidate_value: serde_yaml_candidate::Value = serde_yaml_candidate::from_str(src).unwrap();
        legacy_value.apply_merge().unwrap();
        candidate_value.apply_merge().unwrap();
        let legacy: MergeDoc = serde_yaml_legacy::from_value(legacy_value).unwrap();
        let candidate: MergeDoc = serde_yaml_candidate::from_value(candidate_value).unwrap();
        let expected = MergeDoc {
            defaults: Service { mode: "safe".into(), retries: 2 },
            server: Service { mode: "safe".into(), retries: 5 },
        };
        assert_eq!(legacy, expected);
        assert_eq!(candidate, expected);
    }

    #[test]
    fn duplicate_key_acceptance_matches_for_typed_and_dynamic_values() {
        let src = "key: first\nkey: second\n";
        let legacy = serde_yaml_legacy::from_str::<BTreeMap<String, String>>(src);
        let candidate = serde_yaml_candidate::from_str::<BTreeMap<String, String>>(src);
        assert_eq!(legacy.is_ok(), candidate.is_ok());
        if let (Ok(legacy), Ok(candidate)) = (legacy, candidate) {
            assert_eq!(legacy, candidate);
        }
        let legacy = serde_yaml_legacy::from_str::<serde_yaml_legacy::Value>(src);
        let candidate = serde_yaml_candidate::from_str::<serde_yaml_candidate::Value>(src);
        assert_eq!(legacy.is_ok(), candidate.is_ok());
        if let (Ok(legacy), Ok(candidate)) = (legacy, candidate) {
            assert_eq!(serde_json::to_value(legacy).unwrap(), serde_json::to_value(candidate).unwrap());
        }
    }

    #[test]
    fn recipe_like_serialization_cross_decodes_for_rollback() {
        let original = Recipe {
            name: "backup".into(), enabled: true,
            labels: BTreeMap::from([("scope".into(), "local".into())]),
            steps: vec![Step::Shell { command: "neoth backup".into() },
                        Step::Http { url: "https://example.invalid/hook".into() }],
        };
        let legacy_text = serde_yaml_legacy::to_string(&original).unwrap();
        let candidate_text = serde_yaml_candidate::to_string(&original).unwrap();
        let legacy_own: Recipe = serde_yaml_legacy::from_str(&legacy_text).unwrap();
        let candidate_own: Recipe = serde_yaml_candidate::from_str(&candidate_text).unwrap();
        let candidate_reads_legacy: Recipe = serde_yaml_candidate::from_str(&legacy_text).unwrap();
        let legacy_reads_candidate: Recipe = serde_yaml_legacy::from_str(&candidate_text).unwrap();
        assert_eq!(legacy_own, original);
        assert_eq!(candidate_own, original);
        assert_eq!(candidate_reads_legacy, original);
        assert_eq!(legacy_reads_candidate, original);
    }
}
