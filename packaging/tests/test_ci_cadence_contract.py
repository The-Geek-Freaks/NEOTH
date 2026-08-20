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


if __name__ == "__main__":
    unittest.main()
