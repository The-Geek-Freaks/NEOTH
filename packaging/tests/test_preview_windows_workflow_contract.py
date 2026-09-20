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
        self.assertIn("timeout-minutes: 360", self.workflow)
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
            ("Build native desktop GUI", 90),
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
        all_rust_prefix = "preview-windows-x64-rust-1.93-static-crt-preview-fast-v1-all-rust-complete-"
        interrupted_prefix = "preview-windows-x64-rust-1.93-static-crt-preview-fast-v1-interrupted-"
        aux_prefix = "preview-windows-x64-rust-1.93-static-crt-preview-fast-v1-aux-complete-"
        cli_prefix = "preview-windows-x64-rust-1.93-static-crt-preview-fast-v1-cli-complete-"
        self.assertIn(all_rust_prefix + lock_key, restore)
        self.assertIn("${{ github.run_id }}-${{ github.run_attempt }}", restore)
        for prefix in (all_rust_prefix, interrupted_prefix, aux_prefix, cli_prefix):
            self.assertIn(prefix, restore)
        self.assertIn(interrupted_prefix + lock_key + "-", restore)
        self.assertLess(restore.index(all_rust_prefix), restore.index(interrupted_prefix))
        self.assertLess(restore.index(interrupted_prefix), restore.index(aux_prefix))
        self.assertLess(restore.index(aux_prefix), restore.index(cli_prefix))

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

    def test_portable_acceptance_is_remote_bounded_post_stage_and_receipted(self) -> None:
        job_prefix = self.workflow.split("\n    steps:", 1)[0]
        self.assertIn(
            "PORTABLE_ACCEPTANCE_RECEIPTS: neoth portable acceptance receipts "
            "${{ github.run_id }} ${{ github.run_attempt }}",
            job_prefix,
        )
        self.assertNotIn("runner.", job_prefix)

        ast = self.step("Parse portable acceptance helpers")
        self.assertIn("if: ${{ runner.os == 'Windows' }}", ast)
        self.assertIn("timeout-minutes: 2", ast)
        self.assertIn("System.Management.Automation.Language.Parser]::ParseFile", ast)
        self.assertIn("portable_acceptance_ast_preflight", ast)
        self.assertIn("FunctionDefinitionAst", ast)
        self.assertIn("$node.Name -eq 'Add-Result'", ast)
        self.assertIn("Add-Result -Results $entries -Name 'empty_collector_binding'", ast)
        self.assertIn("$entries.Count -ne 1", ast)
        self.assertIn("receipt_binding_check", ast)
        self.assertIn("$node.Name -eq 'Get-TextSha256'", ast)
        self.assertIn("$emptySha = Get-TextSha256 -Text ''", ast)
        self.assertIn("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ast)
        self.assertIn("packaging/tests/Test-PortablePreview.ps1", ast)
        self.assertIn("packaging/tests/Test-PortableDiffImpact.ps1", ast)
        self.assertIn(
            "$receiptRoot = Join-Path $env:RUNNER_TEMP $env:PORTABLE_ACCEPTANCE_RECEIPTS",
            ast,
        )

        lifecycle = self.step("Portable preview lifecycle acceptance")
        self.assertIn("id: portable_preview_lifecycle", lifecycle)
        self.assertIn("if: ${{ runner.os == 'Windows' }}", lifecycle)
        self.assertIn("timeout-minutes: 30", lifecycle)
        self.assertIn("SLINT_BACKEND: software", lifecycle)
        self.assertIn("dist/neoth-unreleased-preview-windows-x64-$env:GITHUB_SHA.zip", lifecycle)
        self.assertIn("-ArchiveSha256 $sidecar", lifecycle)
        self.assertIn("-ExpectedSourceSha $env:GITHUB_SHA", lifecycle)
        self.assertIn("-GuiRuntimeProbe", lifecycle)
        self.assertIn("portable_preview_lifecycle_ci", lifecycle)
        self.assertIn("neoth_executable=$neoth", lifecycle)
        self.assertIn("packaging/tests/Test-PortablePreview.ps1", lifecycle)
        self.assertIn(
            "$receiptRoot = Join-Path $env:RUNNER_TEMP $env:PORTABLE_ACCEPTANCE_RECEIPTS",
            lifecycle,
        )

        diff_impact = self.step("Portable diff-impact acceptance")
        self.assertIn("if: ${{ runner.os == 'Windows' }}", diff_impact)
        self.assertIn("timeout-minutes: 25", diff_impact)
        self.assertIn("${{ steps.portable_preview_lifecycle.outputs.neoth_executable }}", diff_impact)
        self.assertIn("packaging/tests/Test-PortableDiffImpact.ps1", diff_impact)
        self.assertIn("portable_diff_impact_ci", diff_impact)
        self.assertIn(
            "$receiptRoot = Join-Path $env:RUNNER_TEMP $env:PORTABLE_ACCEPTANCE_RECEIPTS",
            diff_impact,
        )

        receipt_upload = self.step("Upload portable acceptance receipts")
        self.assertIn("if: ${{ always() && runner.os == 'Windows' }}", receipt_upload)
        self.assertIn("timeout-minutes: 5", receipt_upload)
        self.assertIn("actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02", receipt_upload)
        self.assertIn(
            "path: ${{ runner.temp }}/${{ env.PORTABLE_ACCEPTANCE_RECEIPTS }}",
            receipt_upload,
        )
        self.assertIn("if-no-files-found: warn", receipt_upload)

        self.assertLess(self.workflow.index("- name: Checkout exact preview source"), self.workflow.index("- name: Parse portable acceptance helpers"))
        self.assertLess(self.workflow.index("- name: Parse portable acceptance helpers"), self.workflow.index("- name: Setup Rust stable"))
        self.assertLess(self.workflow.index("- name: Stage unreleased preview with source and payload inventory"), self.workflow.index("- name: Portable preview lifecycle acceptance"))
        self.assertLess(self.workflow.index("- name: Portable preview lifecycle acceptance"), self.workflow.index("- name: Portable diff-impact acceptance"))
        self.assertLess(self.workflow.index("- name: Portable diff-impact acceptance"), self.workflow.index("- name: Upload unreleased preview artifact"))
        self.assertLess(self.workflow.index("- name: Upload unreleased preview artifact"), self.workflow.index("- name: Upload portable acceptance receipts"))

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
