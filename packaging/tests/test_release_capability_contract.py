from __future__ import annotations

from pathlib import Path
import re
import tomllib
import unittest


ROOT = Path(__file__).parents[2]
CORE_MANIFEST = ROOT / "SRC" / "neothd" / "Cargo.toml"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"

DESKTOP_TARGETS = {
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
}
HEADLESS_TARGETS = {"x86_64-unknown-linux-musl"}


def release_matrix(workflow: str) -> dict[str, dict[str, bool]]:
    job = re.search(
        r"(?ms)^  build:\n.*?^      matrix:\n        include:\n"
        r"(?P<body>.*?)(?=^    steps:)",
        workflow,
    )
    if job is None:
        raise AssertionError("release build matrix not found")

    entries: dict[str, dict[str, bool]] = {}
    for match in re.finditer(
        r"(?ms)^          - target: (?P<target>\S+)\n"
        r"(?P<body>.*?)(?=^          - target: |\Z)",
        job.group("body"),
    ):
        body = match.group("body")
        use_cross = re.search(r"^            use_cross: (true|false)$", body, re.M)
        include_gui = re.search(r"^            include_gui: (true|false)$", body, re.M)
        if use_cross is None or include_gui is None:
            raise AssertionError(f"incomplete release matrix entry: {match.group('target')}")
        entries[match.group("target")] = {
            "use_cross": use_cross.group(1) == "true",
            "include_gui": include_gui.group(1) == "true",
        }
    return entries


def workflow_step(workflow: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^      - name: {re.escape(name)}\n(?P<body>.*?)(?=^      - name: |\Z)",
        workflow,
    )
    if match is None:
        raise AssertionError(f"release workflow step not found: {name}")
    return match.group("body")


class ReleaseCapabilityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = tomllib.loads(CORE_MANIFEST.read_text(encoding="utf-8"))
        cls.workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        cls.ci_workflow = CI_WORKFLOW.read_text(encoding="utf-8")

    def test_desktop_bundle_selects_the_exact_iroh_feature_leaf(self) -> None:
        features = self.manifest["features"]

        self.assertIn("release-server", features["release-desktop"])
        self.assertIn("cluster-iroh", features["release-desktop"])
        self.assertNotIn("cluster-iroh", features["release-server"])
        self.assertNotIn("cluster-iroh", features["default"])
        self.assertSetEqual(set(features["cluster-iroh"]), {"cluster", "dep:iroh"})

        iroh = self.manifest["dependencies"]["iroh"]
        self.assertEqual(iroh["version"], "1")
        self.assertIs(iroh["optional"], True)

    def test_ssh_tunnel_is_a_patched_opt_in_with_a_locked_ci_contract(self) -> None:
        features = self.manifest["features"]
        russh = self.manifest["dependencies"]["russh"]

        self.assertListEqual(features["ssh-tunnel"], ["dep:russh"])
        for bundle in ("default", "release-server", "release-desktop"):
            with self.subTest(bundle=bundle):
                self.assertNotIn("ssh-tunnel", features[bundle])

        self.assertEqual(russh["version"], "0.62.4")
        self.assertIs(russh["optional"], True)
        self.assertIs(russh["default-features"], False)
        self.assertSetEqual(set(russh["features"]), {"ring"})

        self.assertIn(
            "- { os: ubuntu-24.04, feature: ssh-tunnel }",
            self.ci_workflow,
        )
        self.assertIn(
            "cargo check -p neoth --locked --features ${{ matrix.feature }}",
            self.ci_workflow,
        )
        self.assertIn(
            "if: matrix.feature == 'ssh-tunnel'",
            self.ci_workflow,
        )
        self.assertIn(
            "cargo test -p neoth --locked --features ssh-tunnel transport::ssh_ "
            "-- --test-threads=1",
            self.ci_workflow,
        )

    def test_every_native_desktop_target_uses_the_desktop_release_path(self) -> None:
        matrix = release_matrix(self.workflow)

        self.assertSetEqual(set(matrix), DESKTOP_TARGETS | HEADLESS_TARGETS)
        for target in DESKTOP_TARGETS:
            with self.subTest(target=target):
                self.assertFalse(matrix[target]["use_cross"])
                self.assertTrue(matrix[target]["include_gui"])
        for target in HEADLESS_TARGETS:
            with self.subTest(target=target):
                self.assertTrue(matrix[target]["use_cross"])
                self.assertFalse(matrix[target]["include_gui"])

    def test_native_and_headless_build_steps_use_named_capability_bundles(self) -> None:
        native = workflow_step(self.workflow, "Build (native)")
        cross = workflow_step(self.workflow, "Build (cross)")

        self.assertIn('if: "!matrix.use_cross"', native)
        self.assertIn(
            "run: cargo build --release --locked --bins --features "
            "release-desktop --target ${{ matrix.target }}",
            native,
        )
        self.assertIn("if: matrix.use_cross", cross)
        self.assertIn(
            "run: cross build --release --locked --bins --features "
            "release-server --target ${{ matrix.target }}",
            cross,
        )


if __name__ == "__main__":
    unittest.main()
