"""Focused source tests for the static W169 extractor; not run locally."""
import importlib.util
import json
import pathlib
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("extract_openclaw_channel_schema.py")
spec = importlib.util.spec_from_file_location("extract_openclaw_channel_schema", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


class SchemaWalkerTests(unittest.TestCase):
    def test_checked_policy_is_exact_and_closed_for_every_fixture_row(self):
        fixture = json.loads((SCRIPT.parent.parent / "SRC/neoth-openclaw-custody/src/fixtures/openclaw_channel_schema_v1.json").read_text())
        policy = json.loads((SCRIPT.parent.parent / "SRC/neoth-openclaw-custody/src/fixtures/openclaw_channel_schema_migration_policy_v1.json").read_text())
        before = json.dumps(fixture["channels"], sort_keys=True, separators=(",", ":"))
        module.validate_migration_policy(fixture["channels"], policy)
        self.assertEqual(sum(len(c["leaves"]) for c in fixture["channels"]), 3252)
        self.assertEqual(sum(leaf.get("scope") == "opaque_subtree" for c in fixture["channels"] for leaf in c["leaves"]), 22)
        self.assertEqual(json.dumps(fixture["channels"], sort_keys=True, separators=(",", ":")), before)

    def test_policy_validation_does_not_overlay_source_inventory(self):
        channels = [{"channel_id": "x", "leaves": [{"path_template": "token", "json_type": "string"}]}]
        policy = self.policy_for({"channel_id":"x","path_template":"token","json_type":"string","scope":"typed_leaf","disposition":"needs_secret","action_id":"neoth_credential_flow","target_path":"credentials.x"})
        before = json.dumps(channels, sort_keys=True, separators=(",", ":"))
        module.validate_migration_policy(channels, policy)
        self.assertEqual(json.dumps(channels, sort_keys=True, separators=(",", ":")), before)

    @staticmethod
    def policy_for(*rows, synthetic=None):
        if synthetic is None:
            synthetic = [
                {"kind":"account_container","disposition":"unsupported","action_id":"requires_account_scoped_runtime"},
                {"kind":"whatsapp_auth_dir_string","channel_id":"whatsapp","path_template":"authDir","json_type":"string","disposition":"needs_relink","action_id":"relink_required"},
                {"kind":"account_container_unmapped","disposition":"unknown","action_id":"blocked_requires_explicit_account_mapping"},
            ]
        return {"policy_name": module.POLICY_NAME, "policy_version": 1, "source": dict(module.POLICY_SOURCE), "rows": list(rows), "synthetic": synthetic}

    def test_policy_refuses_missing_extra_and_duplicate_identities(self):
        channels = [{"channel_id": "x", "leaves": [{"path_template": "token", "json_type": "string"}]}]
        row = {"channel_id":"x","path_template":"token","json_type":"string","scope":"typed_leaf","disposition":"needs_secret","action_id":"neoth_credential_flow","target_path":"credentials.x"}
        cases = (
            (self.policy_for(), "missing migration policy identity"),
            (self.policy_for(row, {**row, "path_template":"extra"}), "extra migration policy identity"),
            (self.policy_for(row, dict(row)), "duplicate migration policy identity"),
        )
        for policy, error in cases:
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                module.validate_migration_policy(channels, policy)

    def test_policy_refuses_identity_outcome_and_target_contract_violations(self):
        channels = [{"channel_id": "x", "leaves": [{"path_template": "token", "json_type": "string"}]}]
        row = {"channel_id":"x","path_template":"token","json_type":"string","scope":"typed_leaf","disposition":"needs_secret","action_id":"neoth_credential_flow","target_path":"credentials.x"}
        cases = (
            ({**row, "json_type":"boolean"}, "missing migration policy identity"),
            ({**row, "scope":"opaque_subtree"}, "missing migration policy identity"),
            ({**row, "disposition":"mapped", "action_id":"neoth_credential_flow"}, "invalid migration policy outcome"),
            ({key: value for key, value in row.items() if key != "target_path"}, "invalid migration policy target"),
            ({**row, "target_path":""}, "invalid migration policy target"),
            ({**row, "target_path":42}, "invalid migration policy target"),
            ({**row, "disposition":"unsupported", "action_id":"requires_neoth_adapter", "target_path":""}, "invalid migration policy target"),
            ({**row, "disposition":"unsupported", "action_id":"requires_neoth_adapter", "target_path":None}, "invalid migration policy target"),
        )
        for altered, error in cases:
            with self.subTest(altered=altered), self.assertRaisesRegex(ValueError, error):
                module.validate_migration_policy(channels, self.policy_for(altered))

    def test_policy_refuses_invalid_name_version_and_source_pins(self):
        row = {"channel_id":"x","path_template":"token","json_type":"string","scope":"typed_leaf","disposition":"needs_secret","action_id":"neoth_credential_flow","target_path":"credentials.x"}
        channels = [{"channel_id": "x", "leaves": [{"path_template": "token", "json_type": "string"}]}]
        cases = (
            ({"policy_name":"wrong"}, "invalid migration policy name"),
            ({"policy_version":2}, "invalid migration policy version"),
            ({"source":{**module.POLICY_SOURCE, "commit":"wrong"}}, "invalid migration policy source pins"),
        )
        for replacement, error in cases:
            policy = self.policy_for(row)
            policy.update(replacement)
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                module.validate_migration_policy(channels, policy)

    def test_policy_refuses_missing_extra_duplicate_and_incompatible_synthetic_entries(self):
        row = {"channel_id":"x","path_template":"token","json_type":"string","scope":"typed_leaf","disposition":"needs_secret","action_id":"neoth_credential_flow","target_path":"credentials.x"}
        channels = [{"channel_id": "x", "leaves": [{"path_template": "token", "json_type": "string"}]}]
        good = self.policy_for(row)["synthetic"]
        cases = (
            (good[1:], "missing migration policy synthetic:account_container"),
            (good + [dict(good[0])], "duplicate migration policy synthetic:account_container"),
            (good + [{"kind":"other","disposition":"needs_secret","action_id":"neoth_credential_flow"}], "unknown migration policy synthetic:other"),
            ([{**good[0], "action_id":"relink_required"}, *good[1:]], "invalid migration policy synthetic outcome:account_container"),
            ([good[0], {**good[1], "json_type":"boolean"}], "invalid migration policy synthetic identity:whatsapp_auth_dir_string"),
        )
        for synthetic, error in cases:
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                module.validate_migration_policy(channels, self.policy_for(row, synthetic=synthetic))

    def test_policy_refuses_unknown_fields_and_boolean_version(self):
        row = {"channel_id":"x","path_template":"token","json_type":"string","scope":"typed_leaf","disposition":"needs_secret","action_id":"neoth_credential_flow","target_path":"credentials.x"}
        channels = [{"channel_id": "x", "leaves": [{"path_template": "token", "json_type": "string"}]}]
        cases = (
            ({"extra": True}, "invalid migration policy fields"),
            ({"policy_version":True}, "invalid migration policy version"),
            ({"rows":[{**row, "extra":True}]}, "invalid migration policy row fields"),
            ({"synthetic":[{**self.policy_for(row)["synthetic"][0], "extra":True}, *self.policy_for(row)["synthetic"][1:]]}, "invalid migration policy synthetic fields:account_container"),
        )
        for replacement, error in cases:
            policy = self.policy_for(row)
            policy.update(replacement)
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                module.validate_migration_policy(channels, policy)

    def test_policy_requires_the_exact_source_derived_secret_ref_family_set(self):
        parent = "credential{anyOf:1}{oneOf:0}"
        channels = [{"channel_id":"x", "leaves":[
            {"path_template":parent + suffix,"json_type":"string"}
            for suffix in (".id", ".source", ".provider")
        ]}]
        rows = [
            {"channel_id":"x","path_template":parent + suffix,"json_type":"string","scope":"typed_leaf","disposition":"unsupported","action_id":"requires_target_contract"}
            for suffix in (".id", ".source", ".provider")
        ]
        family = {"kind":"secret_ref_family","channel_id":"x","path_template":parent,"disposition":"needs_secret","action_id":"neoth_credential_flow","target_path":"credentials.x"}
        module.validate_migration_policy(channels, self.policy_for(*rows, synthetic=[*self.policy_for()["synthetic"], family]))
        unsupported = {"kind":"secret_ref_family","channel_id":"x","path_template":parent,"disposition":"unsupported","action_id":"requires_target_contract"}
        module.validate_migration_policy(channels, self.policy_for(*rows, synthetic=[*self.policy_for()["synthetic"], unsupported]))
        cases = (
            ([], "missing migration policy secret_ref_family"),
            ([family, dict(family)], "duplicate migration policy secret_ref_family"),
            ([{**family, "path_template":"other{anyOf:1}{oneOf:0}"}], "missing migration policy secret_ref_family"),
            ([family, {**family, "path_template":"other{anyOf:1}{oneOf:0}"}], "extra migration policy secret_ref_family"),
            ([{**family, "action_id":"requires_neoth_adapter", "target_path":"credentials.x"}], "invalid migration policy secret_ref_family outcome"),
            ([{**family, "target_path":""}], "invalid migration policy secret_ref_family outcome"),
        )
        base = self.policy_for()["synthetic"]
        for families, error in cases:
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                module.validate_migration_policy(channels, self.policy_for(*rows, synthetic=[*base, *families]))

    def test_secret_ref_family_requires_the_complete_typed_source_trio(self):
        parent = "credential{anyOf:1}{oneOf:0}"
        channels = [{"channel_id":"x", "leaves":[
            {"path_template":parent + suffix,"json_type":"string"}
            for suffix in (".id", ".source")
        ]}]
        rows = [
            {"channel_id":"x","path_template":parent + suffix,"json_type":"string","scope":"typed_leaf","disposition":"unsupported","action_id":"requires_target_contract"}
            for suffix in (".id", ".source")
        ]
        family = {"kind":"secret_ref_family","channel_id":"x","path_template":parent,"disposition":"needs_secret","action_id":"neoth_credential_flow","target_path":"credentials.x"}
        with self.assertRaisesRegex(ValueError, "extra migration policy secret_ref_family"):
            module.validate_migration_policy(channels, self.policy_for(*rows, synthetic=[*self.policy_for()["synthetic"], family]))
    def test_resolves_refs_composition_arrays_and_account_template(self):
        root = {
            "definitions": {"secret": {"type": "string"}},
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "defaultAccount": {"type": "string"},
                "accounts": {"type": "object", "propertyNames": {"type": "string"}, "additionalProperties": {"type": "object", "additionalProperties": False, "properties": {"token": {"$ref": "#/definitions/secret"}}}},
                "modes": {"anyOf": [{"type": "array", "items": {"type": "boolean"}}, {"type": "null"}]},
            },
        }
        leaves, blockers = [], []
        module.walk(root, root, "", leaves, blockers, set())
        self.assertEqual(blockers, [])
        self.assertEqual(
            {row["path_template"] for row in leaves},
            {"defaultAccount", "accounts.{key}.token", "modes{anyOf:0}[]", "modes{anyOf:1}"},
        )

    def test_reports_external_refs_and_unknown_schema_nodes(self):
        leaves, blockers = [], []
        module.walk({"$ref": "https://example.invalid/schema"}, {"$ref": "https://example.invalid/schema"}, "x", leaves, blockers, set())
        self.assertEqual(leaves, [])
        self.assertEqual(blockers, [{"path": "x", "reason": "external_ref:https://example.invalid/schema"}])

    def test_static_string_chunks_decode_without_javascript_evaluation(self):
        payload = json.dumps([{"pluginId": "x", "channelId": "x", "schema": {"type": "boolean"}}])
        source = f'const RAW_BUNDLED_CHANNEL_CONFIG_METADATA = [{payload!r}].join("");'
        self.assertEqual(module.decode_static_metadata(source.encode())[0]["channelId"], "x")
        with self.assertRaises((ValueError, SyntaxError)):
            module.decode_static_metadata(b'const RAW_BUNDLED_CHANNEL_CONFIG_METADATA = [__import__("os")].join("");')

    def test_git_blob_uses_actual_nul_framing(self):
        self.assertEqual(module.git_blob(b""), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")

    def test_manifest_pin_matches_the_real_custody_fixture(self):
        fixture = SCRIPT.parent.parent / "SRC/neoth-openclaw-custody/src/fixtures/pinned_channel_inventory_v1.json"
        self.assertEqual(module.digest(fixture.read_bytes()), module.INVENTORY_SHA256)

    def test_missing_and_true_additional_properties_are_blocked(self):
        for root in ({"type": "object"}, {"type": "object", "additionalProperties": True}):
            leaves, blockers = [], []
            module.walk(root, root, "", leaves, blockers, set())
            self.assertEqual(blockers[0]["reason"], "open_additional_properties")

    def test_composition_and_ref_siblings_cannot_be_silently_omitted(self):
        for keyword, extra in (("type", "string"), ("patternProperties", {}), ("not", {})):
            for base in ({"anyOf": [{"type": "string"}]}, {"$ref": "#/definitions/x", "definitions": {"x": {"type": "string"}}}):
                root = {**base, keyword: extra}
                leaves, blockers = [], []
                module.walk(root, root, "", leaves, blockers, set())
                self.assertEqual(leaves, [])
                self.assertIn("unsupported_schema_keyword:" + keyword, [row["reason"] for row in blockers])

    def test_unknown_object_and_scalar_keywords_are_blocked(self):
        for root in ({"type": "object", "additionalProperties": False, "patternProperties": {}}, {"type": "string", "not": {"const": "x"}}):
            leaves, blockers = [], []
            module.walk(root, root, "", leaves, blockers, set())
            self.assertEqual(leaves, [])
            self.assertTrue(any(row["reason"].startswith("unsupported_schema_keyword:") for row in blockers))

    def test_recursive_reference_stops_when_path_grows(self):
        root = {"type": "object", "additionalProperties": False, "properties": {"next": {"$ref": "#"}}}
        leaves, blockers = [], []
        module.walk(root, root, "", leaves, blockers, set())
        self.assertEqual(blockers, [{"path": "next", "reason": "recursive_schema_cycle"}])

    def test_tuple_open_tail_is_not_ignored(self):
        root = {"type": "array", "items": [{"type": "string"}]}
        leaves, blockers = [], []
        module.walk(root, root, "", leaves, blockers, set())
        self.assertEqual(blockers[0]["reason"], "open_additional_items")

    def test_empty_schema_preserves_opaque_account_subtree_without_mapping_claim(self):
        root = {"type": "object", "additionalProperties": False, "properties": {
            "accounts": {"type": "object", "propertyNames": {"type": "string"}, "additionalProperties": {}},
        }}
        leaves, blockers = [], []
        module.walk(root, root, "", leaves, blockers, set())
        self.assertEqual(blockers, [])
        self.assertEqual(leaves, [{"path_template": "accounts.{key}", "json_type": "any", "scope": "opaque_subtree", "disposition": "blocked_requires_explicit_leaf_mapping"}])


if __name__ == "__main__":
    unittest.main()
