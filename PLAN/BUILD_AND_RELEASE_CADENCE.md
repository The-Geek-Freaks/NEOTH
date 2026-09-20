# NEOTH 1.0 build and release cadence

This contract keeps the Road-to-Gold build wave fast without weakening the
evidence required for the public `v1.0.0` tag.

## Workstation stability constraint — 2026-09-16

All local validation workloads on Shadow-PC are suspended after another reported
bluescreen and a confirmed unexpected restart at 14:31 local time on 2026-09-16.
The event records a bugcheck, but its cause has not been established. Earlier
job-count, priority and free-memory limits did not establish safe operation.
Do not run local Cargo, rustc, rustfmt, Clippy, linkers, Python/PowerShell tests,
Git test fixtures, product executables or GUI probes. Use bounded source/metadata
reads, file edits and serialized Git/GitHub operations only. Run formatting,
contracts, builds and behavior gates on GitHub-hosted CI from reviewed commits
on `main`. Prior local results remain historical evidence, not authorization to
repeat them. A commit with pending remote gates must say so explicitly and cannot
satisfy a release gate. This host-specific restriction supersedes all local
validation portions of the evidence ladder below; it does not waive the gates.

The macOS compile step records bounded memory, swap and compiler-process metrics,
preserves Cargo's actual exit status, and uploads diagnostics even on failure.
The observer changes neither compile deadlines nor the workspace test graph.

W107 (2026-09-20) increases only the GitHub-hosted Windows test compile bound
from 50 to 80 minutes after run `35113128375` exhausted the previous limit.
The job retains one compiler worker, serial test execution and the separate
30-minute test window; its outer bound is 120 minutes, leaving 10 minutes for
setup/cache/upload. The prior interrupted cache remains a build input, never
test evidence. macOS completed 16810 tests in that prior run (16805 pass, five
fail, 23 skipped); its existing bounds remain unchanged. New-source full CI is
required after the observed regressions are repaired.

W109 cancels only the known-uncompilable W107 CI/preview source after completed
jobs expose concrete errors. Both cancellations were read back as completed.
After the reviewed Matrix configuration and four compile repairs are published,
new exact-source Preflight/Code Quality precede a fresh full CI and preview.
Successful earlier-source component jobs remain historical evidence.

## Unreleased Windows preview

`.github/workflows/preview-windows.yml` is a manual GitHub-hosted x64 build for
portable CLI/GUI acceptance while local compilation is suspended. It uses one
Cargo job and the locked desktop release feature profile on Rust 1.93.0, then
packages the native binaries, Keet companion, configuration examples and license
notices. Matrix 0.18 requires Rust 1.93, so the main release build matrix uses
the same pin for both desktop and server feature bundles. Default-feature CI,
metadata parsing and the isolated signer retain Rust 1.91. The preview sets
static MSVC CRT linkage and the full source SHA for every native Cargo build.
The preview alone sets `preview-fast-v1` Cargo release-profile overrides:
`opt-level=1`, `debug=0`, `lto=false`, and `codegen-units=16`. The final release
profile in `SRC/Cargo.toml` and the release workflow remain unchanged. Preview
provenance records Rust 1.93.0 and all four overrides; it is not evidence of
optimized-release performance.

The preview job has a 330-minute outer bound. Its CLI, migration/relay and GUI
build steps have independent 90/15/60-minute bounds. Declared bounded steps total
302 minutes, including remote acceptance, leaving 28 minutes for setup and runner
overhead. Preview `35100765685` actually exhausted its previous 45-minute GUI
limit after the core compile completed late in that step. The current-source
recovery grants 15 additional GUI minutes while preserving the same reserve;
it does not claim a measured warm-cache completion time. Compatible cache prefixes
include the compiler, static CRT, preview
profile and lock hash. Restore order is fully completed Rust, interrupted,
completed auxiliary, then completed CLI. The interrupted snapshot from the prior
GUI timeout includes work absent from the earlier auxiliary snapshot; Cargo must
still validate fingerprints and complete each ordinary build command. Only a
successful build phase writes its completed cache. Recovery inputs never prove
a completed binary or an acceptance result.

Tracked `packaging/tests/Test-PortablePreview.ps1` and `Test-PortableDiffImpact.ps1`
are parsed on the GitHub Windows runner before any compilation (2-minute bound).
The same preflight exercises only their extracted receipt/hash functions with
an empty collector and empty process output; their script entry points remain
unexecuted until the actual staged artifact is available.
After normal ZIP/sidecar staging, lifecycle acceptance (30 minutes) verifies the
archive checksum, source/profile provenance and every inventory entry before
extraction. It then exercises read-only absence, refresh/fresh/stale, corrupt
state with explicit repair, root isolation and the software-rendered GUI runtime
probe. Diff-impact acceptance (25 minutes) receives only that verified extracted
CLI and exercises real Git/source indexing, exact symbols/callers, observed-test
provenance and stale-input rejection. Both use fresh spaced runner-temp paths,
isolated `NEOTH_HOME` and 120-second child-process limits. Receipt upload runs even
on failure (5 minutes); upload success alone is not an acceptance result.

Preview `35113132073` completed every native build and Keet staging, then failed
the first lifecycle JSON parse because the real CLI wrote a startup log to
stdout. W107 moves both diagnostic formats to stderr, keeping JSON acceptance
strict. The unchanged lifecycle and diff-impact helpers must pass on the new
artifact; completed compilation of the prior artifact does not satisfy them.

The artifact records the full source commit, each payload file SHA-256 and a
separate ZIP checksum. It is unsigned and unreleased. It does not create a tag,
GitHub Release, installer or release-bound self-knowledge snapshot. Runtime
acceptance uses the actual hash-verified staged ZIP on the runner and is separate
from downloaded-artifact custody, visual/accessibility, installed-product and
final release acceptance. Push preflight checks the workflow contract without
compiling Rust. On the affected workstation none of these helpers may run locally.

## Generated CLI reference during remote-only validation

The existing Gold smoke job exports `neoth completions --reference` from the
CLI binary it already built. The `generated-cli-reference` artifact contains
that exact Markdown, its SHA-256 and the full source commit. Import it only
after matching the source commit and digest. The ordinary
`cli_commands_md_is_up_to_date` regression remains the anti-drift authority;
an exported artifact is not evidence that the committed documentation matches.
The export within full CI adds no compiler invocation. When a newer CLI source
needs its generated snapshot while an earlier full matrix is still running,
the manual-only `cli-reference.yml` workflow builds just `neoth` with one Cargo
worker, reusing the Gold smoke cache read-only. It never writes the repository
or bypasses the docgen test. Neither path executes a local product binary.

## Evidence ladder

NEOTH tests every shipped capability and every advertised platform contract,
not the Cartesian product of every provider, channel, architecture and Linux
distribution. A source change invalidates only the evidence that depends on
that source. The next broader gate runs once after the affected source set is
frozen.

| Boundary | Required evidence | Deliberately deferred |
| --- | --- | --- |
| Edit loop | File-scoped formatter/parser checks and the smallest affected unit or contract filter | Workspace linking, installers and cross-OS jobs |
| Bounded commit | Affected-crate `cargo check`, focused behavior regressions, static wiring/packaging contracts and independent review | Release profile and distro matrix |
| Source-frozen package/GUI wave | Strict Clippy and complete tests for the affected crates/features; GUI test binary linked once | Native installer matrix |
| Workstream/protocol milestone | Full Linux workspace plus only the affected native OS/feature/transport jobs | Public artifacts |
| Weekly/manual milestone | Complete three-OS CI; Security/CodeQL when authority, dependency, unsafe or release boundaries changed | Tag/release publication |
| Unchanged release candidate | Full CI, Security and CodeQL on one exact SHA | Any further source edits |
| Tagged artifact set | Build every release target once; package and test only those downloaded bytes | Any compile inside a clean-machine smoke job |

`source-frozen` means that no file contributing to a package, protocol,
generated asset or embedded release identity changes after its consolidated
gate begins. A later documentation-only edit does not invalidate an unrelated
binary result; a later source, build-script, lockfile, packaging or embedded
knowledge change does.

## During feature and wiring work

Every pull request targeting `main` and every push to `main` runs
`.github/workflows/preflight.yml`:

- locked Cargo metadata without dependency compilation;
- workspace formatting;
- offline packaging, release, provider-parity, and lost-feature contracts;
- checked-in shell syntax.

The PR/push preflight must not compile, link, or execute the Rust workspace. Each
bounded implementation slice still receives targeted local/static verification
and an independent code review before commit.

The complete `.github/workflows/ci.yml` matrix runs:

- for pull requests;
- once per week to expose accumulated integration drift;
- on explicit milestone or release-candidate dispatch.

The complete `.github/workflows/security.yml` matrix runs:

- once per week;
- on explicit release-candidate dispatch.

It intentionally does not run with repository security-state permissions in a
pull-request-controlled context. Pull requests receive the full read-only CI
matrix; the privileged SARIF upload and repository-wide CodeQL alert gate stay
on the trusted weekly/manual Security path.

An interface, protocol, schema, packaging, dependency, unsafe-code, or
cross-process authority change is a milestone and may justify an immediate
manual full run. A documentation-only or isolated static-contract commit does
not.

## Native workspace test phases

The Linux workspace test step runs under `xvfb-run --auto-servernum`, with
`xvfb` and `xauth` installed by the existing dependency step. This supplies a
display for the real Slint/Winit callback acceptance test while retaining the
complete nextest selection and its normal failure status. A headless runner's
missing `DISPLAY` must not be handled by skipping the callback test or replacing
its native backend. Fresh CI must validate the workflow after a change.

The Windows platform-test step selects `SLINT_BACKEND=software` while retaining
the real Winit event loop. For local Gold validation, one fresh, hash-bound
GUI test binary runs its complete
suite with one test thread; a same-binary catalogue accounts for every `ok` and
`ignored` result and requires both the GUI coding controller-to-ProviderWorker
loopback and the W58 Buddy callback fixture to pass. This is software-renderer
runtime evidence only. It does not establish visual or accessibility acceptance.

For coding-result provenance changes, the focused native route uses Cargo package
`neoth` with `--lib` (whose library target is `neothd`); `-p neothd` is not a
substitute. The selection retains **25 filters** and binds all **35 mandatory
fixtures** to the admitted source before execution. The GUI identity uses package
`neothd-gui` and binary `neothd-gui`; it exercises the selected-home service
route, three provider turns, a valid nonempty diff, and durable context/output
commitment assertions. Focused acceptance does not replace broader consumer,
provider, apply, delivery or release gates.

The macOS generated-Slint callback fixtures need the native event loop on the
process main thread. Its CI compile, discovery and execution commands therefore
enable `neothd-gui/macos-native-gui-test`. The custom `harness = false` target
exposes the same five W58 test names to Nextest and runs the selected fixture
directly from `main`; the sixth controller fixture remains ordinary libtest.
Discovery must bind all five names to the custom binary and reject missing or
duplicate registrations before execution. These remain actual Winit/AppKit
fixtures. Test helpers are compiled only under `cfg(test)`; the normal application
entry is unchanged. A custom-target invocation on another platform must never
start the GUI. Windows and Linux keep their ordinary callback test registrations.
The macOS custom target is intended for Nextest; unsupported direct invocations
fail rather than launch the application. Compilation, discovery and fresh JUnit
execution must all pass before this harness supplies acceptance evidence.

The macOS and Windows CI jobs compile the locked workspace test profile with
`cargo nextest run --workspace --locked --profile ci --no-run`, then execute
the complete suite in a separate step against the same checkout and target
cache. The execution step retains the platform's test-thread setting and adds
`--no-tests=fail`, so an empty selection cannot satisfy the gate.

| Platform | Compile limit | Execution limit | Whole-job limit |
| --- | --- | --- | --- |
| macOS | 100 minutes | 30 minutes | 140 minutes |
| Windows | 50 minutes | 30 minutes | 90 minutes |

Windows uses one Cargo build job and one test thread after the four-job build
in CI `34881450745` exhausted the runner's memory before tests could start.
macOS uses one Cargo build job and four test threads. Runs `34881450745` and
`34892993263` exhausted the existing 100-minute compile limit at four jobs.
The measured two-job experiment, CI `35070262418`, again reached the 100-minute
compile boundary before tests while the observer recorded a 6,164.12 MiB swap
peak out of 7,168 MiB and sustained paging with active `rustc` processes. Its
completed job log establishes neither an OOM termination nor a compiler
diagnostic. One build job is therefore the next bounded concurrency experiment;
the compile, execution and job deadlines stay unchanged. The compatible
interrupted cache from that attempt remains a recovery input only: Cargo
freshness is rechecked, and neither that cache nor this tuning is acceptance.
Both platforms keep
the existing pinned toolchain, locked dependency graph, `ci` profile, and full
workspace coverage. The second invocation still checks Cargo freshness and
reuses the artifacts from the compile phase.

The job removes `target/nextest/ci/junit.xml` before compilation and retains
the unconditional JUnit upload. A failed compile therefore cannot publish a
successful report left in the cache by an older run.

This split addresses the observed cold-cache macOS boundary in CI run
`34803269509`: compilation and startup consumed 83m59s, and the former combined
90-minute step timed out before the suite finished. That run also reported a
fixture failure and remains failed evidence. The new cadence requires a fresh,
complete CI run; changing these limits does not establish a passing result.

The combined Cargo registry, git and workspace-target cache first restores a
same-lock partial cache, then the prior exact combined-cache key, then its
broad legacy prefix. Only a completed `cargo nextest ... --no-run` may write
the immutable exact complete key. A failed or timed-out compile may write a
unique run-and-attempt partial key; it is fallback-only material, so it cannot
poison the complete key. Cargo fingerprints remain the authority for reuse. A
later full CI run must still complete the unchanged compile and execution
bounds before it counts as macOS evidence.

## Final Gold verification

Keep local proposal directories limited to their declared source files and
small review artifacts. Do not copy workspace `target` directories or whole
dependency trees into a proposal. After a batch is verified and published,
remove confirmed disposable copies and temporary outputs while retaining the
required verification evidence and the current reusable build cache.

After every mandatory checkbox in `PLAN/ROAD_TO_1_0_GOLD.md` is complete, freeze
one release-candidate commit. Do not rebuild from a different commit between
these gates:

1. Dispatch full CI on the exact candidate SHA.
2. Dispatch Security and CodeQL on the same SHA.
3. Require both runs to be fresh and successful.
4. Create the release tag on that unchanged SHA.
5. Build each target artifact once in `release.yml`.
6. Package installers from those downloaded artifacts.
7. Run clean-machine install, launch, upgrade, rollback, and uninstall probes
   against those same artifacts.
8. Publish only if every required platform and capability receipt belongs to
   the tagged artifact set.

`release.yml` remains fail-closed: a fast Preflight result can never substitute
for the fresh exact-head CI and Security evidence.

## Required final platform coverage

The following is the acceptance matrix that must exist before Gold, not a claim
that the current open R4-01 workflow already proves it. NEOTH must test every
promised support class, not every Linux distribution with the same test suite.

- The final matrix must run the full Rust workspace tests once per
  operating-system semantics class:
  Windows, macOS, and Linux. Feature/transport matrices add only the relevant
  compile or focused behavioral probes.
- Architecture-specific builds and clean-machine journeys must prove Windows x64
  and ARM64, macOS Intel and Apple Silicon, Linux GNU x64 and ARM64, plus the
  headless musl contract without rerunning the whole workspace suite.
- Debian/Ubuntu clean machines must test the DEB transaction and desktop
  runtime.
- Fedora/RHEL-family clean machines must test the RPM transaction and desktop
  runtime.
- A glibc-floor machine must test the portable GNU archive.
- Alpine must test the headless musl archive.
- Windows and macOS clean machines must test their native signed installer,
  first-run GUI/CLI choice, surface switching, start-menu/application launch,
  upgrade, rollback, and uninstall.

Those future distro jobs must consume the already-built artifact. They must not
rebuild NEOTH or repeat the entire workspace test suite. Additional
distributions will either be covered by the documented portable fallback or
will not be advertised until a clean-machine receipt exists.

## Closed acceptance receipts

Every final artifact smoke job must emit one machine-verifiable JSON receipt
containing the schema version, tag, commit SHA, artifact and installer
SHA-256, platform/architecture/ABI or package class, previous/current version,
executed journey IDs, code/self-knowledge identity, start/end state, result and
timestamp. The release DAG must reject missing, duplicate, unknown or
digest-mismatched receipts before signing or publication.

The required receipt set includes:

- portable GNU on the documented oldest supported glibc class;
- headless musl inside pinned Alpine rather than only on an Ubuntu host;
- DEB through `apt` on Debian/Ubuntu semantics;
- RPM through `dnf` on Fedora/RHEL semantics;
- Windows x64/ARM64 native installer, first-run/surface switching, real
  `N -> N+1`, rollback and uninstall;
- macOS Intel/Apple Silicon signed/notarized package, first-run/surface
  switching, real `N -> N+1`, rollback and uninstall.

The artifact producer, installer packager and smoke runner may be separate
jobs, but the receipt must bind them to the same immutable bytes. A same-version
reinstall is useful idempotency evidence and is not accepted as an upgrade or
rollback proof.
