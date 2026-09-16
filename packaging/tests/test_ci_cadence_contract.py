from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
CI_TEXT = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
PREFLIGHT_TEXT = (WORKFLOWS / "preflight.yml").read_text(encoding="utf-8")
RELEASE_TEXT = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
SECURITY_TEXT = (WORKFLOWS / "security.yml").read_text(encoding="utf-8")


def trigger_block(workflow: str) -> str:
    normalized = workflow.replace("\r\n", "\n")
    match = re.search(
        r"(?ms)^on:\n(?P<triggers>.*?)(?=^(?:concurrency|permissions|env|jobs):)",
        normalized,
    )
    if match is None:
        raise AssertionError("workflow has no bounded top-level on block")
    return match.group("triggers")


def used_actions(workflow: str) -> list[tuple[str, str]]:
    return re.findall(r"(?m)^\s*uses:\s*([^@\s]+)@([^\s#]+)", workflow)


def run_commands(workflow: str) -> list[str]:
    normalized = workflow.replace("\r\n", "\n")
    commands: list[str] = []
    lines = normalized.splitlines()
    index = 0
    while index < len(lines):
        match = re.match(r"^(\s*)run:\s*(.*)$", lines[index])
        if match is None:
            index += 1
            continue
        indent, value = match.groups()
        if value != "|":
            commands.append(value.strip())
            index += 1
            continue
        block_indent = len(indent) + 2
        index += 1
        block: list[str] = []
        while index < len(lines):
            line = lines[index]
            if line and len(line) - len(line.lstrip()) < block_indent:
                break
            block.append(line[block_indent:] if line else "")
            index += 1
        commands.append("\n".join(block).rstrip())
    return commands


def event_block(workflow: str, event: str) -> str | None:
    lines = trigger_block(workflow).splitlines()
    for index, line in enumerate(lines):
        if re.match(rf"^  {re.escape(event)}:", line) is None:
            continue
        block = [line]
        for child in lines[index + 1 :]:
            if re.match(r"^  \S", child):
                break
            block.append(child)
        return "\n".join(block).rstrip()
    return None


def workflow_jobs(workflow: str) -> dict[str, str]:
    normalized = workflow.replace("\r\n", "\n")
    parts = normalized.split("\njobs:\n", maxsplit=1)
    if len(parts) != 2:
        raise AssertionError("workflow has no jobs mapping")
    return dict(
        re.findall(
            r"(?ms)^  ([A-Za-z0-9_-]+):\n" r"(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
            parts[1],
        )
    )


def workflow_steps(job: str) -> dict[str, str]:
    steps_match = re.search(r"(?ms)^    steps:\n(?P<steps>.*)\Z", job)
    if steps_match is None:
        raise AssertionError("workflow job has no steps list")
    return dict(
        re.findall(
            r"(?ms)^      - name: (?P<name>[^\n]+)\n"
            r"(?P<body>.*?)(?=^      - name:|\Z)",
            steps_match.group("steps"),
        )
    )


def direct_mapping_keys(mapping: str, indent: int) -> list[str]:
    prefix = " " * indent
    keys: list[str] = []
    for line in mapping.splitlines():
        if not line.startswith(prefix) or line.startswith(prefix + " "):
            continue
        field = line[indent:]
        if not field or field.lstrip().startswith("#"):
            continue
        key, separator, _ = field.partition(":")
        if not separator:
            raise AssertionError(f"workflow mapping field is missing a colon: {line!r}")
        keys.append(key.strip().strip("'\""))
    return keys


def mapping_block(mapping: str, key: str, indent: int) -> str:
    prefix = " " * indent
    match = re.search(
        rf"(?ms)^{re.escape(prefix)}{re.escape(key)}:\s*\n"
        rf"(?P<body>.*?)(?=^{re.escape(prefix)}\S[^\n]*:|\Z)",
        mapping,
    )
    if match is None:
        raise AssertionError(f"workflow mapping has no {key!r} block")
    return match.group("body")


def step_run_command(step: str) -> str:
    match = re.search(
        r"(?m)^        run: \|\n(?P<run>(?:^          [^\n]*(?:\n|\Z)|^\n)*)",
        step,
    )
    if match is None:
        raise AssertionError("workflow step has no block run command")
    return "\n".join(line[10:] for line in match.group("run").splitlines()).rstrip("\n")


def job_dependencies(body: str) -> set[str]:
    match = re.search(r"(?m)^    needs:(?P<inline>[^\n]*)$", body)
    if match is None:
        return set()
    inline = match.group("inline").strip()
    if inline.startswith("[") and inline.endswith("]"):
        return {
            dependency.strip()
            for dependency in inline[1:-1].split(",")
            if dependency.strip()
        }
    if inline:
        return {inline}
    tail = body[match.end() :].splitlines()
    dependencies: set[str] = set()
    for line in tail:
        item = re.fullmatch(r"      - ([A-Za-z0-9_-]+)", line)
        if item is not None:
            dependencies.add(item.group(1))
            continue
        if line.strip():
            break
    return dependencies


def transitive_dependencies(jobs: dict[str, str], job: str) -> set[str]:
    result: set[str] = set()
    pending = list(job_dependencies(jobs[job]))
    while pending:
        dependency = pending.pop()
        if dependency in result:
            continue
        if dependency not in jobs:
            raise AssertionError(f"unknown workflow dependency {dependency!r}")
        result.add(dependency)
        pending.extend(job_dependencies(jobs[dependency]))
    return result


class CiCadenceContractTests(unittest.TestCase):
    def test_preflight_is_the_only_main_push_workflow_in_this_contract(self) -> None:
        preflight = trigger_block(PREFLIGHT_TEXT)
        self.assertRegex(preflight, r"(?m)^  pull_request:\s*$")
        self.assertRegex(preflight, r"(?m)^  push:\s*$")
        self.assertRegex(preflight, r"(?m)^  workflow_dispatch:\s*$")
        self.assertEqual(
            event_block(PREFLIGHT_TEXT, "pull_request"),
            "  pull_request:\n    branches: [main]",
        )

        ci_triggers = trigger_block(CI_TEXT)
        self.assertNotRegex(ci_triggers, r"(?m)^  push:\s*$")
        self.assertRegex(ci_triggers, r"(?m)^  pull_request:\s*$")
        self.assertRegex(ci_triggers, r"(?m)^  schedule:\s*$")
        self.assertRegex(ci_triggers, r"(?m)^  workflow_dispatch:\s*$")

        security_triggers = trigger_block(SECURITY_TEXT)
        self.assertNotRegex(security_triggers, r"(?m)^  push:\s*$")
        self.assertNotRegex(security_triggers, r"(?m)^  pull_request:\s*$")
        self.assertRegex(security_triggers, r"(?m)^  schedule:\s*$")
        self.assertRegex(security_triggers, r"(?m)^  workflow_dispatch:\s*$")

        expected_push_blocks = {
            "preflight.yml": "  push:\n    branches: [main]",
            "release.yml": "\n".join(
                [
                    "  push:",
                    "    tags:",
                    "      - 'v[0-9]+.[0-9]+.[0-9]+'        # stable, e.g. v1.0.0",
                    "      - 'v[0-9]+.[0-9]+.[0-9]+-*'      # validated immediately: -alpha.N / -beta.N / -rc.N, N=0..31",
                ]
            ),
        }
        actual_push_blocks = {
            path.name: block
            for pattern in ("*.yml", "*.yaml")
            for path in WORKFLOWS.glob(pattern)
            if (block := event_block(path.read_text(encoding="utf-8"), "push"))
            is not None
        }
        self.assertEqual(actual_push_blocks, expected_push_blocks)

    def test_preflight_only_runs_allowlisted_noncompiling_commands(self) -> None:
        self.assertEqual(
            run_commands(PREFLIGHT_TEXT),
            [
                "python3 packaging/tests/test_arrayref_provenance_gate.py",
                "python3 packaging/arrayref_provenance_gate.py",
                "cargo metadata --locked --no-deps --format-version 1 > /dev/null",
                "cargo fmt --all -- --check",
                "\n".join(
                    [
                        'deny_dir="$RUNNER_TEMP/neoth-preflight-deny"',
                        'mkdir -p "$deny_dir"',
                        "for tool in cargo rustc rustup cc gcc clang c++ ld cmake make ninja npm npx pnpm yarn bun docker podman; do",
                        "  printf '%s\\n' '#!/usr/bin/env sh' \\",
                        "    'echo \"build tool denied by NEOTH push preflight\" >&2' \\",
                        "    'exit 97' > \"$deny_dir/$tool\"",
                        '  chmod 0755 "$deny_dir/$tool"',
                        "done",
                        'echo "$deny_dir" >> "$GITHUB_PATH"',
                    ]
                ),
                "\n".join(
                    [
                        "python3 packaging/tests/test_ci_cadence_contract.py",
                        "python3 packaging/tests/test_generate_release_manifests.py",
                        "python3 packaging/tests/test_openclaw_provider_parity.py",
                        "python3 packaging/tests/test_publish_crates_contract.py",
                        "python3 packaging/tests/test_roadmap_release_gate.py",
                        "python3 packaging/tests/test_release_asset_contract.py",
                        "python3 packaging/tests/test_release_capability_contract.py",
                        "python3 packaging/tests/test_release_gate_contract.py",
                        "python3 packaging/test_bootstrap_verifier.py",
                        "python3 .github/release-tools/test-release-isolation.py",
                        "python3 scripts/test_lost_feature_integrity.py",
                    ]
                ),
                "\n".join(
                    [
                        "while IFS= read -r -d '' script; do",
                        '  bash -n "$script"',
                        "done < <(git ls-files -z '*.sh')",
                    ]
                ),
            ],
            "push preflight commands and invoked scripts must remain explicitly allowlisted",
        )

    def test_preflight_actions_are_exact_and_immutable(self) -> None:
        self.assertEqual(
            used_actions(PREFLIGHT_TEXT),
            [
                (
                    "actions/checkout",
                    "34e114876b0b11c390a56381ad16ebd13914f8d5",
                ),
                (
                    "actions/setup-python",
                    "a26af69be951a213d495a4c3e4e4022e16d87065",
                ),
                (
                    "dtolnay/rust-toolchain",
                    "4be7066ada62dd38de10e7b70166bc74ed198c30",
                ),
            ],
        )

    def test_security_privileged_jobs_are_main_only(self) -> None:
        jobs = workflow_jobs(SECURITY_TEXT)
        self.assertEqual(
            set(jobs),
            {
                "trusted-main",
                "advisory-exception-gate",
                "audit",
                "deny",
                "bridge-audit",
                "codeql",
                "codeql-javascript",
                "codeql-gate",
                "trivy",
            },
        )
        trusted_main = jobs.pop("trusted-main")
        self.assertNotIn("security-events:", trusted_main)
        self.assertIn(
            'if [[ "$GITHUB_REF" != "refs/heads/main" ]]; then',
            trusted_main,
        )
        self.assertIn(
            "::error::Privileged Security must run from refs/heads/main",
            trusted_main,
        )
        self.assertIn("exit 1", trusted_main)

        for name, body in jobs.items():
            self.assertRegex(
                body,
                r"(?m)^    if: github\.ref == 'refs/heads/main'\s*$",
                f"privileged Security job {name} must reject non-main dispatches",
            )
            expected_needs = {
                "advisory-exception-gate": r"(?m)^    needs: trusted-main\s*$",
                "audit": r"(?m)^    needs: \[trusted-main, advisory-exception-gate\]\s*$",
                "deny": r"(?m)^    needs: \[trusted-main, advisory-exception-gate\]\s*$",
                "codeql-gate": r"(?m)^    needs: \[trusted-main, codeql, codeql-javascript\]\s*$",
            }.get(name, r"(?m)^    needs: trusted-main\s*$")
            self.assertRegex(
                body,
                expected_needs,
                f"privileged Security job {name} must depend on the failing main-ref gate",
            )

    def test_security_audit_keeps_json_failures_diagnosable(self) -> None:
        self.assertEqual(
            direct_mapping_keys(SECURITY_TEXT, 0),
            ["name", "on", "concurrency", "permissions", "env", "jobs"],
        )
        workflow_env = mapping_block(SECURITY_TEXT, "env", 0)
        self.assertEqual(direct_mapping_keys(workflow_env, 2), ["CARGO_TERM_COLOR"])
        self.assertEqual(
            re.findall(
                r"(?m)^  CARGO_TERM_COLOR: ([^\s#]+)\s*(?:#.*)?$", workflow_env
            ),
            ["always"],
        )
        audit_job = workflow_jobs(SECURITY_TEXT)["audit"]
        self.assertEqual(
            direct_mapping_keys(audit_job, 4),
            ["if", "needs", "name", "runs-on", "steps"],
        )
        audit_steps = workflow_steps(audit_job)
        install = audit_steps["Install cargo-audit"]
        run = audit_steps["Run cargo-audit"]

        self.assertEqual(direct_mapping_keys(install, 8), ["uses", "with"])
        self.assertEqual(direct_mapping_keys(run, 8), ["working-directory", "run"])

        self.assertEqual(
            re.findall(r"(?m)^        uses: ([^\s#]+)\s*(?:#.*)?$", install),
            ["taiki-e/install-action@43aecc8d72668fbcfe75c31400bc4f890f1c5853"],
        )
        self.assertEqual(
            re.findall(r"(?m)^          tool: ([^\s#]+)\s*$", install),
            ["cargo-audit@0.22.2"],
        )
        self.assertEqual(
            re.findall(r"(?m)^        working-directory: ([^\s#]+)\s*$", run),
            ["SRC"],
        )

        command = step_run_command(run)
        self.assertEqual(
            command,
            "\n".join(
                [
                    "set -euo pipefail",
                    "cargo audit --json | tee /tmp/audit-result.json",
                    "cargo audit",
                ]
            ),
        )
        for line in command.splitlines():
            if re.search(r"(?:^|\s)cargo\s+audit(?:\s|$)", line):
                self.assertNotRegex(
                    line,
                    r"(?:\b2\s*(?:>>?|>&)|&>|\|&)",
                    "cargo-audit stderr must remain directly visible",
                )

    def test_release_still_requires_fresh_exact_head_full_gates(self) -> None:
        self.assertIn(
            "CI_RUN=$(freshest_exact_head_run ci.yml CI)",
            RELEASE_TEXT,
        )
        self.assertIn(
            "SECURITY_RUN=$(freshest_exact_head_run security.yml Security)",
            RELEASE_TEXT,
        )
        jobs = workflow_jobs(RELEASE_TEXT)
        release_root = "verify-release-version"
        self.assertIn(
            "python packaging/roadmap_release_gate.py --release-tag",
            jobs[release_root],
        )
        self.assertNotIn("continue-on-error:", jobs[release_root])
        for job in jobs:
            self.assertNotRegex(
                jobs[job],
                r"(?m)^    if:",
                f"release job {job} may not conditionally bypass a failed root gate",
            )
            self.assertNotRegex(
                jobs[job],
                r"(?m)^    continue-on-error:",
                f"release job {job} may not ignore its own failed gate",
            )
            if job == release_root:
                continue
            self.assertIn(
                release_root,
                transitive_dependencies(jobs, job),
                f"release job {job} can bypass the Road-to-Gold root gate",
            )
        self.assertIn('-f head_sha="$RELEASE_SHA"', RELEASE_TEXT)
        self.assertIn('and .conclusion == "success"', RELEASE_TEXT)

    def test_platform_test_compilation_and_execution_have_separate_budgets(self) -> None:
        platform_tests = workflow_jobs(CI_TEXT)["platform-tests"]
        self.assertIn("timeout-minutes: ${{ matrix.job_timeout_minutes }}", platform_tests)
        self.assertIn("CARGO_BUILD_JOBS: ${{ matrix.build_jobs }}", platform_tests)
        self.assertNotIn("nextest_timeout_minutes", platform_tests)
        self.assertIn(
            "\n".join(
                [
                    "          - os: macos-14",
                    "            # Runs 34881450745 and 34892993263 timed out compiling at four jobs.",
                    "            build_jobs: 2",
                    "            test_threads: 4",
                    "            junit_name: macos",
                    "            test_build_timeout_minutes: 100",
                    "            test_execution_timeout_minutes: 30",
                    "            # Compile + execute bounds plus checkout/toolchain/cache/setup.",
                    "            job_timeout_minutes: 140",
                ]
            ),
            platform_tests,
        )
        self.assertIn(
            "\n".join(
                [
                    "          - os: windows-2022",
                    "            # Run 34881450745: rustc-LLVM OOM while compiling at four jobs.",
                    "            build_jobs: 1",
                    "            # Localhost port-binding tests race on Windows under parallel",
                    "            # process execution; serial execution preserves the real contract.",
                    "            test_threads: 1",
                    "            junit_name: windows",
                    "            test_build_timeout_minutes: 50",
                    "            test_execution_timeout_minutes: 30",
                    "            # Compile + execute bounds plus checkout/toolchain/cache/setup.",
                    "            job_timeout_minutes: 90",
                ]
            ),
            platform_tests,
        )

        steps = workflow_steps(platform_tests)
        build = steps["Compile nextest workspace test binaries"]
        execute = steps["Run nextest workspace tests"]
        self.assertIn("id: compile-tests", build)
        self.assertEqual(
            direct_mapping_keys(build, 8),
            ["id", "timeout-minutes", "shell", "working-directory", "run"],
        )
        self.assertEqual(
            direct_mapping_keys(execute, 8),
            ["timeout-minutes", "shell", "working-directory", "env", "run"],
        )
        self.assertIn(
            "timeout-minutes: ${{ matrix.test_build_timeout_minutes }}", build
        )
        self.assertIn(
            "timeout-minutes: ${{ matrix.test_execution_timeout_minutes }}", execute
        )
        self.assertIn(
            "\n".join(
                [
                    "        env:",
                    "          # The hosted Windows runner exposes Winit but no usable OpenGL entry points.",
                    "          # Exercise the same real callback/event-loop path with Slint's compiled software renderer.",
                    "          SLINT_BACKEND: ${{ runner.os == 'Windows' && 'software' || '' }}",
                ]
            ),
            execute,
        )
        self.assertEqual(direct_mapping_keys(mapping_block(execute, "env", 8), 10), ["SLINT_BACKEND"])
        self.assertEqual(execute.count("SLINT_BACKEND:"), 1)
        self.assertEqual(
            step_run_command(build),
            "\n".join(
                [
                    "rm -f target/nextest/ci/junit.xml",
                    'if [[ "$RUNNER_OS" != "macOS" ]]; then',
                    "  cargo nextest run --workspace --locked --profile ci --no-run",
                    "  exit 0",
                    "fi",
                    "",
                    'diagnostic_log="$RUNNER_TEMP/macos-nextest-compile-observability.log"',
                    ': > "$diagnostic_log"',
                    "cargo nextest run --workspace --locked --profile ci --no-run &",
                    "cargo_pid=$!",
                    'sleeper_pid=""',
                    "cleanup_observer() {",
                    '  if [[ -n "$sleeper_pid" ]] && kill -0 "$sleeper_pid" 2>/dev/null; then',
                    '    kill "$sleeper_pid" 2>/dev/null || true',
                    '    wait "$sleeper_pid" 2>/dev/null || true',
                    "  fi",
                    "}",
                    "trap cleanup_observer EXIT",
                    "next_snapshot=0",
                    'while kill -0 "$cargo_pid" 2>/dev/null; do',
                    "  if (( SECONDS >= next_snapshot )); then",
                    "    {",
                    '      echo "=== $(date -u +%FT%TZ) ==="',
                    "      sysctl vm.swapusage || true",
                    "      vm_stat || true",
                    '      echo "pid ppid cpu_percent rss_kib elapsed role"',
                    "      ps -axo pid=,ppid=,%cpu=,rss=,etime=,comm= \\",
                    "        | awk '{ role = $6; sub(/^.*\\//, \"\", role); if (role == \"cargo\" || role == \"cargo-nextest\" || role == \"rustc\" || role == \"clang\" || role == \"ld\") print $1, $2, $3, $4, $5, role }' || true",
                    '    } >> "$diagnostic_log"',
                    "    next_snapshot=$((SECONDS + 60))",
                    "  fi",
                    "  sleep 1 &",
                    "  sleeper_pid=$!",
                    '  wait "$sleeper_pid" || true',
                    '  sleeper_pid=""',
                    "done",
                    'wait "$cargo_pid"',
                ]
            ),
        )
        self.assertEqual(
            step_run_command(build).count(
                "cargo nextest run --workspace --locked --profile ci --no-run"
            ),
            2,
            "non-macOS stays direct while macOS runs the identical Cargo argv as an owned child",
        )
        observability = steps["Upload macOS compile observability"]
        self.assertEqual(
            direct_mapping_keys(observability, 8), ["if", "uses", "with"]
        )
        self.assertIn("if: always() && runner.os == 'macOS'", observability)
        self.assertIn(
            "uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
            observability,
        )
        self.assertIn("name: macos-nextest-compile-observability", observability)
        self.assertIn(
            "path: ${{ runner.temp }}/macos-nextest-compile-observability.log",
            observability,
        )
        self.assertIn("if-no-files-found: warn", observability)
        self.assertIn("retention-days: 14", observability)
        self.assertEqual(
            step_run_command(execute),
            "cargo nextest run --workspace --locked --profile ci --test-threads ${{ matrix.test_threads }} --no-tests=fail",
        )
        self.assertNotIn("--no-run", step_run_command(execute))
        self.assertNotIn("junit.xml", step_run_command(execute))
        compile_step = platform_tests.index("Compile nextest workspace test binaries")
        junit_cleanup = platform_tests.index("rm -f target/nextest/ci/junit.xml")
        compile_command = platform_tests.index(
            "cargo nextest run --workspace --locked --profile ci --no-run"
        )
        runtime_step = platform_tests.index("Run nextest workspace tests")
        runtime_command = platform_tests.index(
            "cargo nextest run --workspace --locked --profile ci --test-threads ${{ matrix.test_threads }} --no-tests=fail"
        )
        self.assertLess(compile_step, junit_cleanup)
        self.assertLess(junit_cleanup, compile_command)
        self.assertLess(compile_command, runtime_step)
        self.assertLess(runtime_step, runtime_command)

        cache_restore = steps["Restore Cargo registry + target"]
        complete_save = steps["Save completed Cargo registry + target"]
        partial_save = steps["Save interrupted Cargo registry + target"]
        self.assertEqual(
            direct_mapping_keys(cache_restore, 8), ["id", "uses", "with"]
        )
        self.assertIn("id: cargo-cache", cache_restore)
        self.assertIn(
            "actions/cache/restore@0057852bfaa89a56745cba8c7296529d2fc39830",
            cache_restore,
        )
        for path in (
            "~/.cargo/registry/index/",
            "~/.cargo/registry/cache/",
            "~/.cargo/git/db/",
            "SRC/target/",
        ):
            self.assertIn(path, cache_restore)
            self.assertIn(path, complete_save)
            self.assertIn(path, partial_save)
        self.assertIn(
            "key: ${{ runner.os }}-1.91-cargo-complete-${{ hashFiles('SRC/Cargo.lock') }}",
            cache_restore,
        )
        self.assertLess(
            cache_restore.index(
                "${{ runner.os }}-1.91-cargo-partial-${{ hashFiles('SRC/Cargo.lock') }}-"
            ),
            cache_restore.index(
                "${{ runner.os }}-1.91-cargo-${{ hashFiles('SRC/Cargo.lock') }}"
            ),
        )
        self.assertLess(
            cache_restore.index(
                "${{ runner.os }}-1.91-cargo-${{ hashFiles('SRC/Cargo.lock') }}"
            ),
            cache_restore.index("${{ runner.os }}-1.91-cargo-\n"),
        )
        self.assertNotIn("restore-keys: |\n            #", cache_restore)
        self.assertIn(
            "if: ${{ !cancelled() && steps.compile-tests.outcome == 'success' && steps.cargo-cache.outputs.cache-hit != 'true' }}",
            complete_save,
        )
        self.assertIn(
            "key: ${{ steps.cargo-cache.outputs.cache-primary-key }}", complete_save
        )
        self.assertIn(
            "if: ${{ !cancelled() && failure() && steps.compile-tests.outcome == 'failure' }}",
            partial_save,
        )
        self.assertIn(
            "key: ${{ runner.os }}-1.91-cargo-partial-${{ hashFiles('SRC/Cargo.lock') }}-${{ github.run_id }}-${{ github.run_attempt }}",
            partial_save,
        )
        complete_save_step = platform_tests.index("Save completed Cargo registry + target")
        partial_save_step = platform_tests.index("Save interrupted Cargo registry + target")
        self.assertLess(compile_step, complete_save_step)
        self.assertLess(complete_save_step, partial_save_step)
        self.assertLess(partial_save_step, runtime_step)

        junit = steps["Upload JUnit report"]
        self.assertIn("if: always()", junit)
        self.assertIn("path: SRC/target/nextest/ci/junit.xml", junit)


if __name__ == "__main__":
    unittest.main()
