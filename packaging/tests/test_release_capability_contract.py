from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess
import tempfile
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

        self.assertEqual(russh["version"], "=0.63.2")
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


    def test_windows_semver_precedence_contract_uses_only_pure_helpers(self) -> None:
        match = re.search(
            r"(?ms)^# BEGIN PURE SEMVER CONTRACT\n(?P<pure>.*?)^# END PURE SEMVER CONTRACT$",
            self.windows_smoke,
        )

        self.assertIsNotNone(match)
        pwsh = shutil.which("pwsh")
        self.assertIsNotNone(pwsh, "hosted packaging contract requires pwsh")
        script = match.group("pure") + r"""
$ErrorActionPreference = 'Stop'
$cases = @(
    @('1.0.0-alpha', '1.0.0-alpha.1', -1),
    @('1.0.0-alpha.1', '1.0.0-alpha.beta', -1),
    @('1.0.0-alpha.beta', '1.0.0-beta', -1),
    @('1.0.0-beta', '1.0.0-beta.2', -1),
    @('1.0.0-beta.2', '1.0.0-beta.11', -1),
    @('1.0.0-rc.1', '1.0.0', -1),
    @('1.0.0-alpha.2', '1.0.0-alpha.10', -1),
    @('1.0.0-alpha', '1.0.0-beta', -1),
    @('1.0.0+build.1', '1.0.0+build.2', 0),
    @('999999999999999999999999.0.0', '1000000000000000000000000.0.0', -1)
)
foreach ($case in $cases) {
    $actual = Compare-StrictSemVer -Left $case[0] -Right $case[1]
    if ($actual -ne [int]$case[2]) {
        throw "unexpected SemVer precedence for '$($case[0])' and '$($case[1])': $actual"
    }
}
foreach ($invalid in @('01.0.0', '1.01.0', '1.0.01', '1.0.0-alpha.01')) {
    if (Test-StrictSemVer -Value $invalid) {
        throw "accepted invalid SemVer '$invalid'"
    }
}
"""
        with tempfile.TemporaryDirectory() as temporary_directory:
            contract = Path(temporary_directory) / "semver-contract.ps1"
            contract.write_text(script, encoding="utf-8")
            result = subprocess.run(
                [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(contract)],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_windows_predecessor_upgrade_lane_is_pinned_and_signed(self) -> None:
        workflow = self.workflow
        smoke = self.windows_smoke
        job = re.search(
            r"(?ms)^  smoke-windows-installer:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
            workflow,
        )

        self.assertIsNotNone(job)
        windows_smoke_job = job.group("body")
        native_smoke = workflow_step(workflow, "Native clean-machine installer smoke")
        for architecture in ("X64", "ARM64"):
            with self.subTest(architecture=architecture):
                self.assertIn(
                    f"NEOTH_WINDOWS_PREDECESSOR_{architecture}_RELEASE_TAG",
                    windows_smoke_job,
                )
                self.assertIn(
                    f"NEOTH_WINDOWS_PREDECESSOR_{architecture}_VERSION",
                    windows_smoke_job,
                )
                self.assertIn(
                    f"NEOTH_WINDOWS_PREDECESSOR_{architecture}_SHA256",
                    windows_smoke_job,
                )
        self.assertIn("https://github.com/$env:GITHUB_REPOSITORY/releases/download/", native_smoke)
        self.assertIn("Invoke-WebRequest -Uri $predecessorUri -OutFile $previousInstaller", native_smoke)
        self.assertIn("Get-FileHash -LiteralPath $previousInstaller -Algorithm SHA256", native_smoke)
        self.assertIn("-TimeoutSec 300", native_smoke)
        self.assertIn(".Hash -ine $predecessor.Sha256", native_smoke)
        self.assertIn("$smokeArguments = @{", native_smoke)
        self.assertIn("$smokeArguments.RequireSignature = [bool]$requireSignature", native_smoke)
        self.assertIn("release tag, version, and SHA-256 must be supplied together", native_smoke)
        self.assertIn("$predecessor.Tag -cne \"v$($predecessor.Version)\"", native_smoke)
        self.assertIn("$smokeArguments.PreviousInstaller = $previousInstaller", native_smoke)
        self.assertIn("$smokeArguments.PreviousVersion = $predecessor.Version", native_smoke)
        self.assertIn("$requireSignature = $true", native_smoke)
        self.assertNotIn("/releases/latest", windows_smoke_job)

        self.assertIn("[string]$PreviousVersion = ''", smoke)
        self.assertIn("PreviousInstaller and PreviousVersion must be supplied together", smoke)
        self.assertIn("function Compare-StrictSemVer", smoke)
        self.assertIn("predecessor version '$PreviousVersion' is not older than candidate '$Version'", smoke)
        self.assertIn("function Assert-InstalledPredecessorVersion", smoke)
        self.assertIn("predecessor neoth --version exited $LASTEXITCODE", smoke)
        self.assertIn("installed predecessor uninstall registration does not report its pinned version", smoke)
        self.assertIn("-ExpectedVersion $PreviousVersion", smoke)

    def test_macos_predecessor_upgrade_lane_is_pinned_and_signed(self) -> None:
        job = re.search(
            r"(?ms)^  smoke-macos-native:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
            self.workflow,
        )

        self.assertIsNotNone(job)
        macos_smoke = job.group("body")
        for architecture in ("X86_64", "ARM64"):
            with self.subTest(architecture=architecture):
                self.assertIn(
                    f"NEOTH_MACOS_PREDECESSOR_{architecture}_RELEASE_TAG",
                    macos_smoke,
                )
                self.assertIn(
                    f"NEOTH_MACOS_PREDECESSOR_{architecture}_VERSION",
                    macos_smoke,
                )
                self.assertIn(
                    f"NEOTH_MACOS_PREDECESSOR_{architecture}_SHA256",
                    macos_smoke,
                )
        self.assertIn(
            "https://github.com/${GITHUB_REPOSITORY}/releases/download/",
            macos_smoke,
        )
        self.assertIn("--connect-timeout 30 --max-time 300", macos_smoke)
        self.assertIn("shasum -a 256", macos_smoke)
        self.assertIn("tr '[:upper:]' '[:lower:]'", macos_smoke)
        self.assertIn("macos_bundle_version()", macos_smoke)
        self.assertIn("macos_version_is_older()", macos_smoke)
        self.assertIn("macos_version_is_older \"$PREVIOUS_VERSION\" \"$VERSION\"", macos_smoke)
        self.assertIn('[[ "$core" =~ ^(0|[1-9][0-9]?)', macos_smoke)
        self.assertIn("alpha|beta|rc", macos_smoke)
        self.assertIn("major <= 99 && minor <= 99 && patch <= 99", macos_smoke)
        self.assertIn("PREVIOUS_BUNDLE_VERSION=$(macos_bundle_version", macos_smoke)
        self.assertIn("CANDIDATE_BUNDLE_VERSION=$(macos_bundle_version", macos_smoke)
        self.assertIn("macOS predecessor version is not older", macos_smoke)
        self.assertIn("pkgutil --check-signature \"$PREVIOUS_PKG\"", macos_smoke)
        self.assertIn("xcrun stapler validate \"$PREVIOUS_PKG\"", macos_smoke)
        self.assertIn("CFBundleVersion", macos_smoke)
        self.assertIn("pkg-version raw", macos_smoke)
        self.assertIn("release_version raw", macos_smoke)
        self.assertIn("historical upgrade requires a signed candidate PKG", macos_smoke)
        self.assertLess(
            macos_smoke.index("trap cleanup EXIT"),
            macos_smoke.index("sudo installer -pkg \"$PREVIOUS_PKG\" -target /"),
        )
        for architecture in ("X86_64", "ARM64"):
            with self.subTest(env_assignment=architecture):
                self.assertIn(
                    f"NEOTH_MACOS_PREDECESSOR_{architecture}_RELEASE_TAG: ${{{{ vars.NEOTH_MACOS_PREDECESSOR_{architecture}_RELEASE_TAG }}}}",
                    macos_smoke,
                )
        self.assertLess(
            macos_smoke.index('pkgutil --check-signature "$PKG"'),
            macos_smoke.index('sudo installer -pkg "$PREVIOUS_PKG" -target /'),
        )
        self.assertLess(
            macos_smoke.index('xcrun stapler validate "$PKG"'),
            macos_smoke.index('sudo installer -pkg "$PREVIOUS_PKG" -target /'),
        )
        self.assertNotIn("/releases/latest", macos_smoke)

    def test_macos_native_version_mapping_contract(self) -> None:
        match = re.search(
            r"(?ms)^          # BEGIN PURE MACOS VERSION CONTRACT\n(?P<pure>.*?)^          # END PURE MACOS VERSION CONTRACT$",
            self.workflow,
        )

        self.assertIsNotNone(match)
        script = "set -euo pipefail\n" + match.group("pure") + r'''
test "$(macos_bundle_version 1.0.0)" = 100.0.99
test "$(macos_bundle_version 1.0.0-alpha.0)" = 100.0.0
test "$(macos_bundle_version 1.0.0-beta.0)" = 100.0.32
test "$(macos_bundle_version 1.0.0-rc.31)" = 100.0.95
macos_version_is_older 1.0.0-alpha.31 1.0.0-beta.0
macos_version_is_older 1.0.0-beta.31 1.0.0-rc.0
macos_version_is_older 1.0.0-rc.31 1.0.0
! macos_version_is_older 1.0.0 1.0.0
! macos_version_is_older 1.0.0-beta.0 1.0.0-alpha.31
! macos_version_is_older 1.0.0 1.0.0-rc.31
! macos_bundle_version 1.0.0-preview.1
! macos_bundle_version 100.0.0
! macos_bundle_version 0.0.1
! macos_bundle_version 18446744073709551617.0.0
! macos_bundle_version 1.0.0.1
! macos_bundle_version $'1.0.0\n1.0.1'
'''
        with tempfile.TemporaryDirectory() as temporary_directory:
            contract = Path(temporary_directory) / "macos-version-contract.sh"
            contract.write_text(script, encoding="utf-8")
            result = subprocess.run(
                ["bash", str(contract)],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
