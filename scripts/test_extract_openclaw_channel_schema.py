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
