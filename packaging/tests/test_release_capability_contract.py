from __future__ import annotations

from pathlib import Path
import re
import tomllib
import unittest


ROOT = Path(__file__).parents[2]
CORE_MANIFEST = ROOT / "SRC" / "neothd" / "Cargo.toml"
GUI_MANIFEST = ROOT / "SRC" / "neothd-gui" / "Cargo.toml"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
UNIX_SOURCE_INSTALLER = ROOT / "scripts" / "install.sh"
WINDOWS_INSTALLER = ROOT / "SRC" / "install.ps1"
WINDOWS_SMOKE = ROOT / "packaging" / "windows" / "smoke-installer.ps1"

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
        cls.gui_manifest = tomllib.loads(GUI_MANIFEST.read_text(encoding="utf-8"))
        cls.workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        cls.ci_workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        cls.unix_source_installer = UNIX_SOURCE_INSTALLER.read_text(encoding="utf-8")
        cls.windows_installer = WINDOWS_INSTALLER.read_text(encoding="utf-8")
        cls.windows_smoke = WINDOWS_SMOKE.read_text(encoding="utf-8")

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

    def test_live_audio_is_a_pinned_desktop_only_capability(self) -> None:
        features = self.manifest["features"]
        dependencies = self.manifest["dependencies"]
        linux_dependencies = workflow_step(
            self.workflow, "Install Linux GUI build dependencies"
        )

        self.assertListEqual(
            features["live-audio"], ["dep:cpal", "dep:tract-onnx"]
        )
        self.assertIn("live-audio", features["release-desktop"])
        for bundle in ("default", "release-server"):
            with self.subTest(bundle=bundle):
                self.assertNotIn("live-audio", features[bundle])

        for dependency, version in (("cpal", "=0.18.2"), ("tract-onnx", "=0.23.8")):
            with self.subTest(dependency=dependency):
                self.assertEqual(dependencies[dependency]["version"], version)
                self.assertIs(dependencies[dependency]["optional"], True)

        self.assertIn("libasound2-dev", linux_dependencies)
        self.assertIn("pkg-config", linux_dependencies)

    def test_ssh_tunnel_is_a_patched_opt_in_with_a_locked_ci_contract(self) -> None:
        features = self.manifest["features"]
        russh = self.manifest["dependencies"]["russh"]

        self.assertListEqual(features["ssh-tunnel"], ["dep:russh"])
        for bundle in ("default", "release-server", "release-desktop"):
            with self.subTest(bundle=bundle):
                self.assertNotIn("ssh-tunnel", features[bundle])

        self.assertEqual(russh["version"], "0.62.5")
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

    def test_matrix_enabled_release_bundles_use_their_required_rust_version(self) -> None:
        features = self.manifest["features"]
        matrix_sdk = self.manifest["dependencies"]["matrix-sdk"]
        build_job = re.search(
            r"(?ms)^  build:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
            self.workflow,
        )

        self.assertEqual(self.manifest["package"]["rust-version"], "1.91")
        self.assertIn("matrix-channel", features["release-server"])
        self.assertIn("release-server", features["release-desktop"])
        self.assertEqual(matrix_sdk["version"], "0.18")
        self.assertIs(matrix_sdk["optional"], True)
        self.assertIsNotNone(build_job)
        self.assertIn("toolchain: '1.93.0'", build_job.group("body"))

    def test_gui_embeds_the_desktop_release_bundle_everywhere(self) -> None:
        gui_features = self.gui_manifest["features"]
        core_dependency = self.gui_manifest["dependencies"]["neothd"]
        desktop_gui = workflow_step(self.workflow, "Build desktop GUI")
        gui_build = (
            "cargo build --release --locked -p neothd-gui "
            "--features release-desktop"
        )

        self.assertListEqual(gui_features["default"], ["gui-loop"])
        self.assertListEqual(
            gui_features["release-desktop"],
            ["neothd/release-desktop"],
        )
        self.assertEqual(core_dependency["package"], "neoth")
        self.assertIs(core_dependency["default-features"], False)
        self.assertIn("cluster", core_dependency["features"])

        self.assertIn("if: matrix.include_gui", desktop_gui)
        self.assertIn(
            f"run: {gui_build} --target ${{{{ matrix.target }}}}",
            desktop_gui,
        )
        self.assertIn(gui_build, self.unix_source_installer)
        self.assertIn(gui_build, self.windows_installer)
        self.assertNotIn(
            "-p neothd-gui -p neoth-migrate",
            self.unix_source_installer,
        )
        self.assertNotIn(
            "-p neothd-gui -p neoth-migrate",
            self.windows_installer,
        )

    def test_windows_clean_machine_code_map_lifecycle_uses_only_the_installed_cli(self) -> None:
        smoke = self.windows_smoke
        installed_call = "Invoke-InstalledCodeMapLifecycleSmoke -Directory $ownedDirectory"

        self.assertIn("function Invoke-InstalledCodeMapLifecycleSmoke", smoke)
        self.assertIn("function Invoke-InstalledNeothJson", smoke)
        self.assertIn("WaitForExit(120000)", smoke)
        self.assertIn("[System.Diagnostics.ProcessStartInfo]::new()", smoke)
        self.assertIn("$startInfo.ArgumentList.Add($argument)", smoke)
        self.assertIn("$startInfo.CreateNoWindow = $true", smoke)
        self.assertIn("$startInfo.RedirectStandardOutput = $true", smoke)
        self.assertIn("$process.StandardOutput.ReadToEndAsync()", smoke)
        self.assertIn("$process.StandardError.ReadToEndAsync()", smoke)
        self.assertIn("$process.Kill($true)", smoke)
        self.assertIn("$env:NEOTH_HOME = $codeMapHome", smoke)
        self.assertIn("$env:NEOTH_HOME = $previousNeothHome", smoke)
        self.assertIn("Join-Path $Directory 'neoth.exe'", smoke)
        self.assertIn("'code-map', 'status', $repoA", smoke)
        self.assertIn("'code-map', 'refresh', $repoA", smoke)
        self.assertIn("'--repair-corrupt'", smoke)
        self.assertIn("'code-map', 'status', $repoB", smoke)
        self.assertIn("lifecycle.state.kind -ne 'absent'", smoke)
        self.assertIn("lifecycle.state.kind -ne 'fresh'", smoke)
        self.assertIn("lifecycle.state.snapshot.index_generation", smoke)
        self.assertIn("lifecycle.state.kind -ne 'stale'", smoke)
        self.assertIn("lifecycle.state.kind -ne 'corrupt'", smoke)
        self.assertIn("lifecycle.state.kind -ne 'unmapped'", smoke)
        self.assertIn("'indexed_first_time'", smoke)
        self.assertIn("'refreshed_stale'", smoke)
        self.assertIn("'corrupt_repair_required'", smoke)
        self.assertNotIn("'IndexedFirstTime'", smoke)
        self.assertNotIn("'RefreshedStale'", smoke)
        self.assertNotIn("'CorruptRepairRequired'", smoke)
        self.assertLess(smoke.index("Assert-Payload -Directory $ownedDirectory"), smoke.index(installed_call))
        self.assertLess(smoke.index(installed_call), smoke.index("Invoke-Uninstall -Directory $ownedDirectory"))
        helper = smoke[smoke.index("function Invoke-InstalledNeothJson"):smoke.index("function Assert-CodeMapGeneration")]
        lifecycle_helper = smoke[smoke.index("function Invoke-InstalledCodeMapLifecycleSmoke"):smoke.index("function Get-InstalledReleaseFingerprint")]
        self.assertIsNone(re.search(r"(?i)\$home\s*=", lifecycle_helper))
        self.assertNotIn("Start-Process", helper)
        self.assertNotIn("-ArgumentList $Arguments", helper)
        self.assertNotIn("neothd-gui.exe') `\n            -ArgumentList '--runtime-probe'", smoke[smoke.index("function Invoke-InstalledCodeMapLifecycleSmoke"):])


if __name__ == "__main__":
    unittest.main()
