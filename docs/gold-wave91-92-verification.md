# W91-W93 - preview recovery, portable acceptance and strict harness lint

Preview run [35080018852](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35080018852)
on `c736c37621e9f0eed4a2819883ad0cc2c3176089` compiled CLI/compatibility binaries
in 81m22s and migration/relay binaries in 2m38s. GUI compilation reached its
25-minute step deadline while compiling dependencies. It did not produce a
portable artifact; no compiler diagnostic or OOM cause was established.

The run saved compatible CLI, auxiliary and interrupted target caches. Restoring
auxiliary before interrupted would discard the later GUI progress. The recovery
now selects a fully completed Rust cache first, then interrupted, auxiliary and
CLI snapshots. Toolchain, CRT mode, preview optimization profile and lock hash
remain part of every compatible prefix. Cargo still validates fingerprints and
must complete all ordinary package-specific commands. Only successful GUI
compilation writes the fully completed Rust cache.

The GUI deadline is 45 minutes and the outer job deadline is 315 minutes. The
bounded steps total 287 minutes, leaving 28 minutes for setup and runner overhead.
One Cargo worker, Rust 1.93.0, static MSVC CRT, locked desktop features and the
preview-only `preview-fast-v1` profile remain. The new timeout is a bounded recovery
attempt, not a claim about the yet-unmeasured warm-cache duration.

Two tracked PowerShell helpers now run on GitHub's Windows runner. An AST preflight
runs before compilation. After normal ZIP staging, lifecycle acceptance verifies
its checksum, inventory and source/profile provenance before extraction, then
checks CLI startup, code-map state transitions, explicit corrupt repair, root
isolation and the GUI runtime probe. Diff-impact acceptance consumes only the
verified extracted executable and checks real Git/index data, exact symbol/caller
impact, observed test evidence, generation/root binding and stale-input rejection.
Both retain isolated homes, fresh space-containing paths and 120-second child
process limits. Step receipts and captured helper output upload even on failure;
that upload does not itself prove any check passed.

The helpers are admitted from the previously reviewed W86 sources with the narrow
addition of fresh paths below `RUNNER_TEMP` when `GITHUB_ACTIONS=true`. No private
workstation path or untracked WORK file is a runtime dependency. Final source
review also corrected the workflow's initial WORK references and retained the
existing contract's correctly escaped step-selection expression.

All formatting, syntax, contracts, builds and runtime acceptance are GitHub-only
after the confirmed workstation restart. Local work in this batch is limited to
bounded source/metadata reads, edits and serialized Git/GitHub operations. The
[source manifest](verification/gold-wave91-92-source-manifest.json) retains prior
committed bindings and adds the two helper inputs (293 cumulative inputs). The
[test matrix](verification/gold-wave91-92-test-matrix.json) retains 49 native and
6 GUI obligations, including the macOS main-thread target identities.

W89 Preflight [35097555802](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35097555802)
and Code Quality [35097554326](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35097554326)
passed on `cc387be72092dc62da1b1965e0a3bf6634b9567c`. Full CI
[35097577183](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35097577183)
is still in progress for that unchanged Rust source. W91/W92's new workflow and
portable helpers require fresh remote gates; no portable, visual, installed or
release acceptance is claimed from source review. No roadmap checkbox closes:
1324 total / 1015 checked / 307 open / 2 partial, raw309 / pre-tag308.

The first admitted W91/W92 commit `442a64af` passed Preflight
[35099504321](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35099504321),
but GitHub rejected its preview workflow before any job in
[35099503167](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35099503167).
The annotation identified `runner.temp` in job-level `env` (line 28), where that
context is unavailable. The existing text contract did not cover that scope.
The correction retains a relative receipt-directory name in job env, joins it
to `RUNNER_TEMP` inside each PowerShell step, and resolves the upload path in
`steps.with`, where the runner context is supported by the
[GitHub context reference](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#context-availability).
A focused regression rejects runner expressions before the steps boundary and
requires every receipt producer and the uploader to use the same path.
No acceptance helper or build setting changes in this correction. Its fresh
remote gate and preview execution are still required; the rejected run started
no compiler and produced no artifact.

A subsequent source review identified two PowerShell parameter-binding problems:
the first receipt appends to an empty mandatory list, and ordinary process output
can be an empty mandatory string. The helpers now explicitly allow these two
valid inputs without weakening path, source, inventory, exit-code or timeout
checks. This follows the documented
[PowerShell parameter attributes](https://learn.microsoft.com/en-us/powershell/scripting/lang-spec/chapter-12#1232-the-allowemptycollection-attribute).
Before any Rust build, the remote preflight extracts only the real `Add-Result`
and `Get-TextSha256` function definitions into isolated scopes. It verifies the
first appended receipt and the known SHA-256 of empty output. It never invokes
helper entry points, archive extraction or product processes in that early check.

Meanwhile, Linux strict Clippy in full CI `35097577183` failed before tests on
six custom-harness diagnostics: one unused shared-source entry, one unnecessary
return and four manual membership scans. W93 replaces the scans with `contains`,
uses a non-macOS tail match and documents a function-local dead-code exception
for the entry that only the explicit custom test target invokes. Ordinary
libtest compiles that same module without dispatching the entry. The five native
macOS callbacks, sixth ordinary fixture and non-macOS no-fallthrough behavior
remain. Independent source review approved this exact one-file correction.
Rust source after W93 therefore needs fresh formatting, strict lint and runtime
proof; the earlier Windows/macOS jobs are retained for diagnostic feedback and
cannot stand in for a new exact-source release gate. No local validation ran.
