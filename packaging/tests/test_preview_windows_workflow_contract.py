from __future__ import annotations

import unittest
from pathlib import Path
import re


WORKFLOW = Path(__file__).parents[2] / ".github" / "workflows" / "preview-windows.yml"


class PreviewWindowsWorkflowContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    @classmethod
    def step(cls, name: str) -> str:
        match = re.search(
            rf"(?ms)^      - name: {re.escape(name)}\n(.*?)(?=^      - name:|\Z)",
            cls.workflow,
        )
        if match is None:
            raise AssertionError(f"preview workflow lacks step {name!r}")
        return match.group(1)

    def test_preview_is_manual_single_job_x64_and_read_only(self) -> None:
        self.assertIn("workflow_dispatch:", self.workflow)
        self.assertIn("contents: read", self.workflow)
        self.assertIn("CARGO_BUILD_JOBS: '1'", self.workflow)
        self.assertIn("RUSTFLAGS: '-C target-feature=+crt-static'", self.workflow)
        self.assertIn("NEOTH_SOURCE_HEAD: ${{ github.sha }}", self.workflow)
        self.assertIn("CARGO_PROFILE_RELEASE_OPT_LEVEL: '1'", self.workflow)
        self.assertIn("CARGO_PROFILE_RELEASE_DEBUG: '0'", self.workflow)
        self.assertIn("CARGO_PROFILE_RELEASE_LTO: 'false'", self.workflow)
        self.assertIn("CARGO_PROFILE_RELEASE_CODEGEN_UNITS: '16'", self.workflow)
        self.assertIn("crt_mode = 'static-msvc-v1'", self.workflow)
        self.assertIn("preview-windows-x64:", self.workflow)
        self.assertEqual(self.workflow.count("\n  preview-windows-x64:"), 1)
        self.assertIn("runs-on: windows-2022", self.workflow)
        self.assertIn("timeout-minutes: 240", self.workflow)
        self.assertIn("toolchain: '1.93.0'", self.workflow)
        self.assertNotIn("push:", self.workflow)
        self.assertNotIn("tags:", self.workflow)
        self.assertNotIn("publish", self.workflow.lower())
        self.assertNotIn("create release", self.workflow.lower())
        self.assertNotIn("secrets.", self.workflow)
        self.assertNotIn("vars.", self.workflow)
        for pinned_action in (
            "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
            "dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30",
            "actions/cache/restore@0057852bfaa89a56745cba8c7296529d2fc39830",
            "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020",
            "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        ):
            self.assertIn(pinned_action, self.workflow)
        self.assertNotIn("Remove-Item", self.workflow)
        self.assertIn("GetFullPath", self.workflow)
        self.assertIn("Refusing to write outside the preview dist directory", self.workflow)
        self.assertIn("Refusing to overwrite preexisting preview output", self.workflow)

    def test_preview_builds_the_complete_native_desktop_payload(self) -> None:
        self.assertIn(
            "cargo build --release --locked --bins --features release-desktop --target x86_64-pc-windows-msvc",
            self.workflow,
        )
        self.assertIn(
            "cargo build --release --locked -p neoth-migrate -p neoth-relay --target x86_64-pc-windows-msvc",
            self.workflow,
        )
        self.assertIn(
            "cargo build --release --locked -p neothd-gui --features release-desktop --target x86_64-pc-windows-msvc",
            self.workflow,
        )
        for executable in (
            "neoth.exe",
            "neothd.exe",
            "neothd-gui.exe",
            "neoth-migrate.exe",
            "neoth-relay.exe",
            "neoth-keet-bridge.exe",
        ):
            self.assertIn(executable, self.workflow)

    def test_preview_fast_profile_has_bounded_phases_and_reusable_complete_caches(self) -> None:
        lock_key = "${{ hashFiles('SRC/Cargo.lock') }}"
        self.assertIn(
            "preview keeps the release feature/profile identity but deliberately\n"
            "    # uses preview-fast-v1 Cargo overrides for bounded feedback only.",
            self.workflow,
        )
        for step_name, timeout in (
            ("Build native CLI and compatibility executables", 90),
            ("Build native migration and relay executables", 15),
            ("Build native desktop GUI", 25),
        ):
            self.assertIn(f"timeout-minutes: {timeout}", self.step(step_name))

        registry_restore = self.step("Restore versioned preview Cargo registry cache")
        self.assertIn("actions/cache/restore@", registry_restore)
        self.assertIn(
            "preview-windows-x64-rust-1.93-static-crt-preview-fast-v1-registry-"
            + lock_key,
            registry_restore,
        )
        self.assertIn("${{ github.run_id }}-${{ github.run_attempt }}", registry_restore)

        restore = self.step("Restore compatible Rust target cache")
        self.assertIn("actions/cache/restore@", restore)
        self.assertIn(
            "preview-windows-x64-rust-1.93-static-crt-preview-fast-v1-all-rust-complete-"
            + lock_key,
            restore,
        )
        self.assertIn("${{ github.run_id }}-${{ github.run_attempt }}", restore)
        for phase in ("all-rust", "aux", "cli"):
            self.assertIn(
                f"preview-windows-x64-rust-1.93-static-crt-preview-fast-v1-{phase}-complete-",
                restore,
            )
        interrupted_prefix = (
            "preview-windows-x64-rust-1.93-static-crt-preview-fast-v1-interrupted-"
        )
        self.assertIn(interrupted_prefix, restore)
        self.assertIn(interrupted_prefix + lock_key + "-", restore)
        self.assertLess(
            restore.index("preview-windows-x64-rust-1.93-static-crt-preview-fast-v1-cli-complete-"),
            restore.index(interrupted_prefix),
        )

        completed = (
            ("Save completed CLI Cargo cache", "cli"),
            ("Save completed migration and relay Cargo cache", "aux"),
            ("Save completed GUI Cargo cache", "all-rust"),
        )
        for step_name, phase in completed:
            step = self.step(step_name)
            self.assertIn("if: ${{ success() }}", step)
            self.assertIn("actions/cache/save@", step)
            self.assertIn(
                f"preview-windows-x64-rust-1.93-static-crt-preview-fast-v1-{phase}-complete-"
                + lock_key
                + "-${{ github.run_id }}-${{ github.run_attempt }}",
                step,
            )

        interrupted = self.step("Save interrupted preview Cargo cache")
        self.assertIn("if: ${{ always() && (failure() || cancelled()) }}", interrupted)
        self.assertIn("actions/cache/save@", interrupted)
        self.assertIn(
            interrupted_prefix + lock_key + "-${{ github.run_id }}-${{ github.run_attempt }}",
            interrupted,
        )

    def test_preview_has_exact_provenance_and_never_claims_installed_acceptance(self) -> None:
        self.assertIn("source_sha = $env:GITHUB_SHA", self.workflow)
        self.assertIn("Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256", self.workflow)
        self.assertIn("SHA256SUMS.json", self.workflow)
        self.assertIn("artifact_kind = 'unreleased_windows_x64_preview'", self.workflow)
        self.assertIn("toolchain = '1.93.0'", self.workflow)
        self.assertIn("build_profile = 'release'", self.workflow)
        self.assertIn("optimization_profile = 'preview-fast-v1'", self.workflow)
        for provenance_override in (
            "cargo_profile_release_opt_level = '1'",
            "cargo_profile_release_debug = '0'",
            "cargo_profile_release_lto = 'false'",
            "cargo_profile_release_codegen_units = '16'",
        ):
            self.assertIn(provenance_override, self.workflow)
        self.assertIn(
            "Build profile: release; preview-fast-v1 overrides opt-level=1, debug=0, lto=false, codegen-units=16.",
            self.workflow,
        )
        self.assertIn("signing = 'none'", self.workflow)
        self.assertIn("github_release = 'not_created'", self.workflow)
        self.assertIn("installer = 'not_created'", self.workflow)
        self.assertIn("installed_acceptance = 'not_run'", self.workflow)
        self.assertNotIn("build-installer.ps1", self.workflow)
        self.assertNotIn("smoke-installer.ps1", self.workflow)


if __name__ == "__main__":
    unittest.main()
