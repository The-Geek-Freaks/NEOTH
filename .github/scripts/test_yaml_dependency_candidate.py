"""Hosted regressions for rejecting unrelated resolver changes."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
from tempfile import TemporaryDirectory

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
            "checksum": gate.CHECKSUM, "dependencies": gate.NEW_YAML_DEPS.copy(),
        }
        self.after[("libyaml-rs", "0.3.0", registry)] = {
            "name": "libyaml-rs", "version": "0.3.0", "source": registry, "checksum": gate.LIBYAML_CHECKSUM,
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

    def lock_fixture(self):
        packages = copy.deepcopy(self.before)
        packages[gate.OLD_SERDE]["checksum"] = gate.OLD_SERDE_CHECKSUM
        packages[gate.OLD_SERDE]["dependencies"] = gate.OLD_SERDE_DEPS.copy()
        packages[gate.OLD_UNSAFE]["checksum"] = gate.OLD_UNSAFE_CHECKSUM
        text = "# unrelated header must survive\nversion = 4\n\n"
        for package in packages.values():
            text += "# fixture package\n[[package]]\n"
            for key, value in package.items():
                if key == "dependencies":
                    text += "dependencies = [\n" + "".join(f' "{edge}",\n' for edge in value) + "]\n"
                else:
                    text += f'{key} = "{value}"\n'
            text += "\n"
        return text.encode()

    def test_lock_edit_preserves_every_unrelated_raw_block_and_line_endings(self):
        for newline in (b"\n", b"\r\n"):
            with self.subTest(newline=newline):
                original = self.lock_fixture().replace(b"\n", newline)
                changed = gate.candidate_lock(original)
                old = gate.re.split(rb"(?m)(?=^\[\[package\]\]\r?$)", original)
                new = gate.re.split(rb"(?m)(?=^\[\[package\]\]\r?$)", changed)
                self.assertEqual(len(old), len(new))
                self.assertEqual(old[0], new[0])
                changes = []
                for before, after in zip(old[1:], new[1:]):
                    identity = next(iter(gate.package_index_data(before)))
                    if identity in {gate.OLD_SERDE, gate.OLD_UNSAFE}:
                        changes.append(identity)
                    elif identity[0] in gate.OWNERS:
                        self.assertEqual(after, before.replace(b'"serde_yaml",', b'"yaml_serde",'))
                        changes.append(identity)
                    else:
                        self.assertEqual(before, after)
                self.assertEqual(len(changes), 6)
                gate.validate_packages(gate.package_index_data(original), gate.package_index_data(changed))
                if newline == b"\r\n":
                    self.assertNotIn(b"\n", changed.replace(b"\r\n", b""))

    def test_lock_edit_rejects_base_pin_and_owner_drift(self):
        base = self.lock_fixture()
        for invalid in (
            base.replace(gate.OLD_SERDE_CHECKSUM.encode(), b"0" * 64),
            base.replace(gate.OLD_UNSAFE_CHECKSUM.encode(), b"0" * 64),
            base.replace(b'"indexmap 2.14.0"', b'"indexmap 2.13.0"'),
            base.replace(b' "serde_yaml",', b' "kept",', 1),
            base.replace(b' "serde_yaml",', b' "serde_yaml",\n "serde_yaml",', 1),
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    gate.candidate_lock(invalid)

    def test_rejects_new_yaml_implementation_checksum_and_dependency_drift(self):
        for changed_key, field, value in (
            (gate.NEW_LIBYAML, "checksum", "0" * 64),
            (gate.NEW_LIBYAML, "dependencies", ["kept"]),
            (gate.NEW_YAML, "dependencies", gate.NEW_YAML_DEPS + ["kept"]),
        ):
            changed = copy.deepcopy(self.after)
            changed[changed_key][field] = value
            with self.subTest(changed_key=changed_key, field=field):
                with self.assertRaises(ValueError):
                    gate.validate_packages(self.before, changed)

    def test_rejects_real_unrelated_edge_version_drift(self):
        self.before[self.kept]["dependencies"] = ["windows-sys 0.59.0"]
        self.after[self.kept]["dependencies"] = ["windows-sys 0.61.2"]
        with self.assertRaisesRegex(ValueError, "unrelated dependency edges"):
            gate.validate_packages(self.before, self.after)

    def test_prepare_validates_all_candidates_before_changing_product_bytes(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            data = {path: b'serde_yaml = "0.9"\n' for path in gate.MANIFESTS}
            data["SRC/Cargo.lock"] = self.lock_fixture()
            data[gate.MANIFESTS[-1]] = b'# no reviewed request\n'
            for relative, content in data.items():
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            with patch.object(gate, "ROOT", root), patch.object(gate, "assert_changed"):
                with self.assertRaisesRegex(ValueError, "expected one serde_yaml"):
                    gate.prepare(root / "proof")
            self.assertEqual(data, {relative: (root / relative).read_bytes() for relative in data})
            self.assertFalse((root / "proof").exists())

    def test_manifest_edit_preserves_all_unrelated_bytes(self):
        original = b'# retained\r\nserde_yaml = "0.9"\r\nkept = "1"\r\n'
        expected = b'# retained\r\nserde_yaml = { package = "yaml_serde", version = "=0.10.7" }\r\nkept = "1"\r\n'
        self.assertEqual(gate.candidate_manifest(original), expected)

    def test_manifest_edit_rejects_duplicate_requests(self):
        with self.assertRaisesRegex(ValueError, "expected one serde_yaml"):
            gate.candidate_manifest(b'serde_yaml = "0.9"\nserde_yaml = "0.9"\n')


if __name__ == "__main__":
    unittest.main()
