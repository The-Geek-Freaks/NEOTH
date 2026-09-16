# W91/W92 - preview cache recovery and GitHub portable acceptance

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
