# NEOTH 1.0 build and release cadence

This contract keeps the Road-to-Gold build wave fast without weakening the
evidence required for the public `v1.0.0` tag.

## Workstation stability constraint — 2026-09-16

Heavy Rust compilation on Shadow-PC is suspended after repeated reported
bluescreens and confirmed unexpected Windows restarts. Job-count, process
priority and free-memory limits did not establish safe operation on this host.
Do not restart local Cargo build, test compilation, Clippy or linker workloads.
Use lightweight formatting/parser, metadata and Python/source checks locally;
run the remaining build and behavior gates on GitHub-hosted CI from reviewed
commits on `main`. A commit with pending remote gates must say so explicitly and
cannot satisfy a release gate. This host-specific restriction supersedes the
local compile portions of the evidence ladder below; it does not waive them.

The macOS compile step records bounded memory, swap and compiler-process metrics,
preserves Cargo's actual exit status, and uploads diagnostics even on failure.
The observer changes neither compile deadlines nor the workspace test graph.

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

The preview job has a 240-minute outer bound. Its CLI, migration/relay and GUI
build steps have independent 90/15/25-minute bounds. All declared bounded steps
total 205 minutes, leaving setup and recovery reserve. Compatible cache prefixes
include the compiler, static CRT, preview profile and lock hash. Run/attempt keys
are immutable; completed phases have priority over interrupted recovery inputs.
Only a successful build phase can save its completed cache. An interrupted cache
does not prove a completed binary or any acceptance result.

The artifact records the full source commit, each payload file SHA-256 and a
separate ZIP checksum. It is unsigned and unreleased. It does not create a tag,
GitHub Release, installer or release-bound self-knowledge snapshot. Its runtime
acceptance must use the downloaded, hash-verified bytes and is separate from
installed-product and final release acceptance. Push preflight checks the
workflow contract without compiling Rust.

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
