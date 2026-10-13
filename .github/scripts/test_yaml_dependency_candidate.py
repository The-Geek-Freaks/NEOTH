"""Hosted regressions for rejecting unrelated resolver changes."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "yaml_candidate", Path(__file__).with_name("yaml-dependency-candidate.py")
)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class CandidateDeltaTests(unittest.TestCase):
    def setUp(self):
        registry = gate.REGISTRY
        self.before = {
            ("serde_yaml", "0.9.34+deprecated", registry): {
                "name": "serde_yaml", "version": "0.9.34+deprecated", "source": registry,
                "checksum": "a" * 64, "dependencies": ["unsafe-libyaml"],
            },
            ("unsafe-libyaml", "0.2.11", registry): {
                "name": "unsafe-libyaml", "version": "0.2.11", "source": registry, "checksum": "b" * 64,
            },
            ("kept", "1.0.0", registry): {
                "name": "kept", "version": "1.0.0", "source": registry, "checksum": "c" * 64,
            },
        }
        for owner in gate.OWNERS:
            self.before[(owner, "1.0.0", "")] = {
                "name": owner, "version": "1.0.0", "dependencies": ["kept", "serde_yaml"],
            }
        self.after = {key: copy.deepcopy(value) for key, value in self.before.items()
                      if key[0] not in {"serde_yaml", "unsafe-libyaml"}}
        for key, package in self.after.items():
            if key[0] in gate.OWNERS:
                package["dependencies"] = ["kept", "yaml_serde"]
        self.after[("yaml_serde", "0.10.7", registry)] = {
            "name": "yaml_serde", "version": "0.10.7", "source": registry,
            "checksum": gate.CHECKSUM, "dependencies": ["libyaml-rs"],
        }
        self.after[("libyaml-rs", "0.3.0", registry)] = {
            "name": "libyaml-rs", "version": "0.3.0", "source": registry, "checksum": "d" * 64,
        }
        self.kept = ("kept", "1.0.0", registry)
        self.yaml = ("yaml_serde", "0.10.7", registry)

    def test_accepts_exact_four_consumer_alias_delta(self):
        result = gate.validate_packages(self.before, self.after)
        self.assertEqual(result["consumers"], sorted(gate.OWNERS))
        self.assertEqual({key[0] for key in result["removed"]}, {"serde_yaml", "unsafe-libyaml"})

    def test_rejects_unrelated_same_name_version_upgrade(self):
        changed = self.after.pop(self.kept)
        changed["version"] = "1.0.1"
        self.after[("kept", "1.0.1", gate.REGISTRY)] = changed
        with self.assertRaisesRegex(ValueError, "unexpected added identities"):
            gate.validate_packages(self.before, self.after)

    def test_rejects_retained_package_checksum_drift(self):
        self.after[self.kept]["checksum"] = "e" * 64
        with self.assertRaisesRegex(ValueError, "metadata/checksum changed"):
            gate.validate_packages(self.before, self.after)

    def test_rejects_unrelated_dependency_edge(self):
        self.after[self.kept]["dependencies"] = ["libyaml-rs"]
        with self.assertRaisesRegex(ValueError, "unrelated dependency edges"):
            gate.validate_packages(self.before, self.after)

    def test_rejects_extra_consumer_dependency(self):
        self.after[("neoth", "1.0.0", "")]["dependencies"].append("libyaml-rs")
        with self.assertRaisesRegex(ValueError, "non-YAML consumer edge"):
            gate.validate_packages(self.before, self.after)

    def test_rejects_wrong_yaml_registry_checksum(self):
        self.after[self.yaml]["checksum"] = "e" * 64
        with self.assertRaisesRegex(ValueError, "pin or checksum differs"):
            gate.validate_packages(self.before, self.after)

    def test_rejects_legacy_yaml_remaining(self):
        legacy_key = ("serde_yaml", "0.9.34+deprecated", gate.REGISTRY)
        self.after[legacy_key] = copy.deepcopy(self.before[legacy_key])
        with self.assertRaisesRegex(ValueError, "unexpected removed identities"):
            gate.validate_packages(self.before, self.after)

    def test_manifest_edit_preserves_all_unrelated_bytes(self):
        original = b'# retained\r\nserde_yaml = "0.9"\r\nkept = "1"\r\n'
        expected = b'# retained\r\nserde_yaml = { package = "yaml_serde", version = "=0.10.7" }\r\nkept = "1"\r\n'
        self.assertEqual(gate.candidate_manifest(original), expected)

    def test_manifest_edit_rejects_duplicate_requests(self):
        with self.assertRaisesRegex(ValueError, "expected one serde_yaml"):
            gate.candidate_manifest(b'serde_yaml = "0.9"\nserde_yaml = "0.9"\n')


if __name__ == "__main__":
    unittest.main()
