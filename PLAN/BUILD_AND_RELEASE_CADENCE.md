# NEOTH 1.0 build and release cadence

This contract keeps the Road-to-Gold build wave fast without weakening the
evidence required for the public `v1.0.0` tag.

**W212 generation isolation (2026-09-22):** model generations now bind artifact
identity, config selection and exact config path through episode claim/write,
SQLite/HNSW recall and consolidation. Model changes requeue eligible episodes;
late results cannot restore superseded vectors. Media and episode spaces remain
separate. Seventeen new tests plus fourteen existing HNSW/forget regressions
bring the grouped lane to 236, with 526 source paths / 783 universal native /
92 GUI identities and unchanged platform extras. Hosted W212 execution is pending.
W211 Grouped205 `35763682082` is fully admitted (205/205, all 46 source paths,
identities, matrix and lock bound to `54c57b19`). Full CI `35765595152` on
`c4176c54` reported 33 Linux slim-Clippy diagnostics under separate repair;
other native jobs remain pending. Road stays 1324 / 1015 checked / 307 open /
2 partial. See `docs/gold-wave212-verification.md`. No local executable checks ran.

**W211 Core pass / GUI compile repair (2026-09-22):** Grouped205
`35763682082` and Core/CLI `35763685944` on `54c57b19` succeeded. The generated
CLI reference is source/SHA-bound and imported. Native CI identified E0425
(callback generation captured in the wrong timer) and E0277 (closure error
inferred as unsized str) in the new GUI path. The minimal fixes are published
with fresh source bindings; post-fix GUI validation remains required. Formatting
from Hosted preflight is already imported as `165a2dd5`. W212 stays unstaged;
Road counts remain 1324 / 1015 checked / 307 open / 2 partial.

**W205 accepted / W211 Hosted formatting (2026-09-22):** Grouped200
`35762299584` on `ff9fe8e2` passed all 200 actual tests; every test identity,
46 source paths, matrix and Cargo.lock match the run. Core/CLI `35762303618`
also passed. W211 is published as `54c57b19`; Grouped205 `35763682082`,
Core/CLI `35763685944` and consolidated native CI `35763722040` are running.
Preflight found formatting only; its exact source/hash-bound patch for three
Rust files is imported without executing a formatter locally. W212 remains
separate uncommitted implementation. Road counts and release acceptance do not change.

**W211 embedding operator surface (2026-09-22):** typed CLI and GUI now expose
selection, cache status, fresh BGE verification and lifecycle actions against
the exact config/home. Cache status never claims Ready; stale results and wrong
model pins are rejected. Five core and five GUI regressions bring inventory to
524 sources / 752 universal native / 92 GUI, with unchanged platform extras;
the grouped lane selects 205. Source review corrections are integrated; Hosted
compile, behavior and GUI rendering remain pending. W210 admitted evidence:
13/13 focused tests, real product CLI pull, official native smoke and retained
Ready recovery; W207 17/17 also passed. W205 full-symbol repair is published at
`ff9fe8e2`, with fresh Grouped200/Core runs `35762299584` / `35762303618` underway.
W212 model-generation isolation is in active implementation. Road remains
1324 / 1015 checked / 307 open / 2 partial. See `docs/gold-wave211-verification.md`.

**W210 Hosted model result and W205 exact-symbol correction (2026-09-22):**
BGE run `35760067844` on `db27a66c` succeeded, including product CLI pull,
native official-model load and the exact smoke/recovery tests; detailed receipt
admission is being finalized. Core/CLI export `35759967854` on `ab2902ec`
succeeded and its source/SHA-bound CLI reference is imported. Grouped200
`35759964957` executed all 200 tests with one remaining W205 failure. The
previous `delegated` fixture correction was insufficient: exact identifier
recall requires `leaf_delegated`, which the real seed publishes in `x.rs`.
The fixture now verifies actual retained repo context before asserting the
mandatory session-bound WAL receipt; no receipt assertion is removed.
W211 embedding GUI/CLI integration is under independent review. Road remains
1324 / 1015 checked / 307 open / 2 partial; no local executable validation ran.

**Hosted consent acceptance and fixture repair (2026-09-22):** Grouped187
`35758426828` on `7209c07d` executed 185 passes / 2 ordinary failures / no
process aborts. All 30 W208 and all 16 W209 behavior tests passed. The three
artifacts, 187 identities across 40 source paths, matrix and Cargo.lock match
the run exactly. Core test-check, public CLI build and export `35758430620`
also passed. The two remaining fixtures had incorrect setup/observation:
W205 must query the full seeded `leaf_delegated` symbol to require a code-map
receipt (`0x26`; `0x25` is SkillRouteResolved). W207's default refusal-recovery
mode publishes its exact final body through `StreamFrames`, not early deltas.
Both mandatory behavioral assertions remain intact with corrected fixture
inputs/output selection. Fresh Grouped200 also validates W210, published at
`bcecdc29`. Road remains 1324 / 1015 checked / 307 open / 2 partial.

**W210 BGE-M3 core/CLI (2026-09-22):** explicit `embed.model=bge_m3` selects
only the verified local official model at immutable revision
`5617a9f61b028005a4858fdac845db406aefb181`. The native Candle PTH adapter,
fixed artifact manifest, D7/D8 acquisition/recovery, instance-bound readiness
and `models bge-m3 list|status|pull|repair|prune` are integrated. Independent
static review passed. Thirteen focused tests bring the grouped lane to 200;
two separate Hosted tests exercise official weights and retained-Ready recovery.
Inventory: 524 source inputs / 747 universal native / 87 GUI identities, with
unchanged platform extras. Execution remains pending; GUI/Buddy parity is W211.
`GOLD-LF-P2-24` stays open. See `docs/gold-wave210-verification.md`.
On `7209c07d`, Grouped187 ran all selected cases and still reports W205/W207
failures; artifact admission is being checked. Core test type-check passed and
the CLI build is running. No local executable validation occurred.

**W209 Hosted compile repair (2026-09-22):** Grouped187 `35757019692` and
Core/CLI `35757023750` on `7ca58b52` stopped at compilation, before behavior
execution. The compiler identified a missing `ChannelRef` import and owned
policy/receipt arguments where references are required. Six narrow corrections
are published with refreshed source/test hashes. Preflight `35757459627` and
CodeQL `35757459117` passed on `92da627a`. Fresh Grouped187/Core execution is
required; the prior 30/30 W208 behavior proof remains bound to `719178ee`.
W210 BGE-M3 core/CLI is in active integration. No Road acceptance box changes.
No local executable validation ran under the workstation BSOD hold.

**Hosted checkpoint (2026-09-22, W208/W209):** Grouped171 `35755005928` on
`719178ee` executed all 171 exact identities: 169 passed, two failed normally,
zero stack aborts. All 30 W208 origin/consumer/migration tests passed. Artifact
source identities, matrix and lock hashes were verified. Core/CLI `35755009718`
also passed. The W207 buffered-output assertion is corrected in `91844f89` and
needs a fresh run. The delegated-channel code-map session assertion remains
open; a bounded status/surface diagnostic preserves the original assertion.
This publication adds the integrated W209 sender request/grant/revoke ceremony,
closed marker-authenticated WAL receipts, additive v43 schema and actual
startup/drain/shutdown audit recovery. Independent integrated static review
passed. Sixteen new focused tests bring the grouped selection to 187 and the
inventory to 519 source inputs / 734 universal native identities / 87 GUI
identities, with unchanged platform extras. Fresh Hosted compile and behavior
are required. The older Windows preview is evidence for `a68442cb` only.
Road remains 1324 total / 1015 checked / 307 open / 2 partial. No local
executable validation ran under the workstation BSOD hold.

**W209 sender-confirmed consent source (2026-09-22):** challenges bind exact
commands, sender, account and confirmation conversation; positive consent
covers that sender/account. Issuance-generation checks reject stale pre-revoke
tokens, while fresh post-revoke consent remains possible. Revoke immediately
quarantines existing derived state and supersedes a pending re-grant without
losing its terminal audit custody. Ambiguous writer results preserve truthful
pending recovery. Ceremony tokens bypass RAW/transcripts/providers and ordinary
writer entry points cannot mint their receipts. Core, migration, real writer
and channel lifecycle/recovery fixtures are inventoried for Hosted execution.
P2-22 and release acceptance remain open. See `docs/gold-wave209-verification.md`.
**W208 origin/consumer source (2026-09-22):** local chat and authenticated
channel RAW now have exact header/session-bound origin receipts. Unknown data
is denied for episode vectors and clustering; local-only construction and
transactional rechecks fence dispatch/storage, revoke and stale HNSW recall.
Projection rejects malformed links without pinning replay, while database errors
roll back the cursor. Independent static review passed. This source slice needs
fresh Hosted execution; the sender-verified consent ceremony is the following
slice, so channel grants remain unavailable and P2-22 stays open. See
`docs/gold-wave208-verification.md`.
**W207 source batch (2026-09-22):** one 120-second meaningful-progress
watchdog now spans provider dispatch and post-reply work. The typed timeout
crosses plain daemon RPC and GUI attach without a competing shorter deadline;
GUI retry guidance survives a partial reply followed by Failed and remains
bound to its subscription generation. Seventeen core and one GUI regressions
plus three W206 budget regressions are added to the source inventory. Independent
static review passed; fresh Hosted compile and behavior remain required.
See `docs/gold-wave207-verification.md`. W208 origin/consumer integration
is published; the W209 ceremony remains uncommitted. No Road box is closed.

**W204/W205 behavior repair and W206 Hosted format (2026-09-22):** the
Grouped101 failure exposed an unchanged wizard snapshot waking its own and
other read-only long-polls. The owner now publishes only changed snapshots;
waiters require their exact session/boot and a newer sequence or terminal state.
A two-reader regression supplements the original mutation test. Ordinary serve
still rejects an incomplete home before WAL startup; its test now checks the
stable GOLD-ADAPT-OH-03 gate and actionable `neoth init` instruction.

The delegated-channel failure exposed admitted repository context being dropped
from the sub-agent bundle. Delegation now retains typed RepoContext alongside
mandatory Block D, while the final budget and retained-context audit remain
authoritative. Its original full integration assertions remain intact, with a
new focused bundle regression. Independent static review passed both repairs.
W206 is published at `4b39a208`; Preflight `35745312836` supplied six formatting
postimages verified against the exact source, receipt hashes and Git object IDs.
Fresh Hosted compile and Grouped121 behavior gates are required. No Road box
closed and no local executable validation ran.

**W206 terminal mirror source (2026-09-22):** structural Right/Cerebellum
analysis now produces an enum-only, deterministic refusal explanation. The
shared prepared-turn call budget, total 4,000-token/USD0.02 operation cap,
configured daily cap and one six-second cancellation-aware deadline all apply
before transport. D23 remains provider-free even with legacy recovery disabled;
0x17 must be durable in the same session before visible replacement. Eighteen
focused regressions and independent static review cover the real authorizer and
chat paths. Hosted W206 compile/format/behavior are pending; P1-02 stays open.
Evidence: `docs/gold-wave206-verification.md`.

**W204/W205 execution checkpoint:** source `862eb030` passed Core test-target
checking, public CLI build and reference export (`35742993700`), Preflight
(`35742932579`) and Code Quality (`35742932102`). The exported CLI reference
is byte-identical to the tracked reference. Grouped101 (`35742990116`) executed
all 101 exact identities: 98 passed, three failed (delegated-channel WAL coverage,
incomplete-home setup diagnostic, and wizard long-poll mutation). Source/input
hashes and every actual test name were verified. Repairs are separate work in
progress; no failed assertion was waived. Road remains 1324 total / 1015 checked /
307 open / 2 partial. No local executable validation ran under the BSOD hold.

**W204 first Hosted compile repair (2026-09-22):** source `40f2e46f` is
published on main. Grouped101 `35741899027` stopped during compilation, before
any selected behavior fixture ran: two missing generic annotations, a private
remove helper returning bool instead of unit, and four test partial moves.
The seven compiler diagnostics are repaired without changing assertions or
session behavior. Preflight `35741875989` supplied formatting for six files;
source HEAD, receipt hashes and exact Git pre/postimages were checked before
import. Code Quality `35741874933` passed. The current source needs fresh
Hosted compile, formatting and behavior checks. No local executable validation
ran; W206 remains uncommitted and Road counts stay unchanged.

**W204 daemon-owned GUI onboarding source (2026-09-22):** first-run setup now
uses `serve --wizard-bootstrap` before ordinary daemon configuration/runtime
startup. A private authenticated Unix socket or Windows pipe admits commands
through a bounded single owner; the completion token stays in the daemon and
`init/io` remains the only marker authority. The GUI retains one session,
submits its real ChannelOverride, observes coalesced sequence-bound snapshots
without holding the mutation lock, and reaches Chat only after Completed.
Prepared config hashing and completion share the canonical transaction lock.
Cancellation, stale boot/sequence, ambiguous response, daemon restart, bounded
admission, terminal response failure, and owner/PID drain have focused tests.
The native owner is joined before task-owned PID release; Guard drop never
blocks the GUI/Tokio thread. Existing Dream readback/revision behavior remains.

Independent static review passed after lifecycle repairs. Fifteen new native
identities and seven GUI identities are recorded with platform gating; their
hosted execution is pending. W204 observes full snapshots, not a lossless event
stream, and supports the existing ChannelOverride input rather than claiming
all hypothetical wizard inputs. P1-18 remains open pending hosted/native GUI
acceptance. No local build, parser, formatter, test or product runtime ran.

W205 source `aced377c` passed Preflight `35740724198` and Code Quality
`35740719898`. Prior `6bf25239` Core/CLI/export `35739731593` passed; Grouped86
`35739726969` executed86, passed85, with only the delegated-channel final-response
fixture still failing. The fixture now explicitly enables its delegated MCP catalogue, preserving the four-tool/child-scope/final-response assertions; rerun remains required. All23 W202 n8n identities passed. The
W206 mirror pipeline remains separate uncommitted work. Road counts remain
1324 total / 1015 checked / 307 open / 2 partial.

**W205 Hosted formatting follow-up (2026-09-22):** source `6bf25239` is on
GitHub main. Preflight `35739707562` exported exactly two formatting hunks;
source HEAD, receipt SHA-256 and full Git pre/postimage identities were checked
before import. The new source-scan collector is inlined at its sole caller to
avoid an eight-argument wrapper while preserving both audits and diagnostics.
Core test-target checking in `35739731593` has passed; public CLI build and
Grouped86 `35739726969` are still active. Code Quality `35739707200` passed.
W204 and W206 remain separate uncommitted work. Road counts stay unchanged.

**W205 Windows fixture contracts / W202 HTTP framing repair (2026-09-22):**
Hosted Grouped83 `35737278608` on `9024b7db` executed all 83 identities: 81
passed, including the strict Cron WAL event-link regression. The two remaining
n8n failures share a mock HTTP framing error: a 29-byte documented JSON body
advertised 28 bytes. Only five fixture headers are corrected; production
validation stays strict. All actual names, source bindings, matrix and lockfile
hashes were checked against the downloaded evidence. The same source passed
Preflight `35737276826` and Code Quality `35737276710`.

The completed older full matrix `35726117022` recorded nine Windows failures
among 17,334 cases and an active macOS compile timeout. W205 fixes four distinct
fixture/inventory contracts: canonical physical materializer path, WAL HMAC
initialization before authenticated installation, explicit Research CLI parity
triage, and the reviewed authorized Research provider-call digest. Independent
static review passed; hosted behavior is pending. Three exact identities join
the grouped selection (86 total); the materializer identity was already selected.
The outbound-source scan now shares each parsed source between both existing audits instead of reparsing the tree repeatedly; its 120-second Windows limit and every check remain unchanged. This performance repair still requires hosted confirmation. Previously repaired
local-model uncertainty, Research budget presence, Drawio routing and WAL-join
issues remain subject to fresh full CI. W204 wizard work remains uncommitted.
Road remains 1324 total / 1015 checked / 307 open / 2 partial. No local compiler,
parser, formatter, tests or product runtime ran.

W195 repairs the 13 failures observed in the completed 17,296-case Windows
run `35713920675`, then requires a fresh full-CI milestone after focused/core
checks. The grouped34 lane first exposed two new fixture/cache compile errors;
those are repaired alongside the exact 48 Hosted formatter hunks. No failed
identity is skipped or removed. Staging/commit/push remain root-only to avoid
shared-index interference; narrow worker-owned source changes stay unstaged.

W196 extends the grouped lane to exactly 38 identities (W19010/W1915/W19210/
W1935/W1944/W1964). Every name must have one current native source record.
Independent behavior failures are retained in failed-fixtures.txt and all selected
identities continue; a nonempty failure receipt makes the final result fail.
Compile/discovery and source-binding failures still stop immediately. This gives
one useful error inventory per build without weakening any pass requirement.


After `0d18bb17` Preflight/Code Quality and `7f2b8636` core test-target/CLI
checks passed, full-CI milestone `35726117022` was dispatched on `0d18bb17`.
It includes the fresh W195 resampler audio matrix. Preserve this run across
ordinary W197/W198 source pushes; those pushes do not dispatch or replace a
full matrix. The grouped38 behavior result remains separately pending. W197
prerequisite admission and W198 n8n session-registry changes need their own
reviewed, source-bound Hosted fixture selection before acceptance.

W197-W200 now require exactly sixty grouped identities: W19010/W1915/W19210/
W1935/W1944/W1964/W19711/W1986/W1995. W197 includes the existing real reload
and metadata-pinning fixtures; W198 includes both existing oversize fixtures.
The literal per-wave map is validated before compilation, and each selected
behavior invocation is limited to 180 seconds plus ten seconds for termination.
This follows the confirmed W191 WAL-join fixture deadlock in run35724290786;
its cancelled fourteen-pass receipt is partial evidence only. The release pass
condition remains all exact selected tests completed successfully. W200 also
repairs the eight observed Linux lint findings without suppressing diagnostics.

W201 corrects four test-compile errors observed in both b7c9 Hosted lanes and
imports twenty-seven exact Hosted format hunks. The sixty-fixture selection is
unchanged. Test-only construction helpers do not widen runtime authority APIs.
The old full matrix's audio jobs now passed 19/19 on all three platforms with
source/input/log custody; preserve its native jobs for their independent results.

W201 follow-up source `737b9835` passed Preflight `35729768850`, Code Quality
`35729767980` and the core test-target check in `35729831467`; the grouped
behavior run and CLI build are still pending. The formerly production-visible
bundled-policy test helper now has `cfg(test)` instead of a lint suppression.
The old `8b654ebd` Windows preview `35713923652` hit the 90-minute GUI build
bound and saved its interrupted cache; no portable acceptance was reached.
Investigate that Hosted limit separately; local validation remains suspended.

W203 follows the actual Grouped60 inventory: 55 executed, 50 passed, five failed,
then a fatal Cron discovery mismatch. Corrected Cron module names retain all
sixty tests. Repairs require another complete grouped run; partial passes do
not close their parent Road criteria. Core/CLI 737b passed and its reference is
byte-identical. Windows GUI preview gets a bounded 120-minute step after the
observed90-minute timeout; GitHub-hosted job ceiling stays360 minutes. No local
validation or reduced acceptance is permitted by these recovery changes.

**W202 n8n adoption source publication (2026-09-22):** the new CLI adopts an
explicit already-running literal-loopback instance through a durable job. The
API key enters through bounded stdin and the existing credential backend;
negative-control rejection and authenticated pre/post-publication API probes
precede Ready. Every active request supports cancellation, failed publication
compensates the exact prior config/secret generation, and restart terminates
unowned work with custody recovery. Status reads stored state without a probe.
Independent final source review passed after cancellation and input fixes.
Twenty-three exact W202 identities join the existing sixty-test Hosted lane.
Compilation, behavior, CLI reference and native acceptance remain pending;
this is not an installer or a Gold/release completion claim. Road remains
1324 total / 1015 checked / 307 open / 2 partial. Local execution stays suspended.
Details: `docs/gold-wave202-verification.md`.

W202 adds exactly 23 source-bound adoption/input/config fixtures (83 grouped total).
Preflight retains its failing format gate and now exports an exact-source rustfmt
patch on format failure; root imports it after HEAD/hash/preimage checks, without
local Rust execution. Historical source receipts remain immutable.

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

W128 adds one hosted optional-adapter lane to the existing feature matrix because
ordinary default-feature CI does not compile the IRC/Nostr adapter modules.
The lane enables `irc-channel nostr-channel` with Rust 1.91 and one Cargo worker,
compiles the library through its focused hermetic tests, and verifies each exact
test identity has one match before execution. Its job/test bounds are 45/40
minutes; live provider and release acceptance remain separate. The workflow and
its existing cadence contract must pass hosted validation before this is counted
as evidence. No local toolchain execution is authorized by the new lane.

W174 adds ffmpeg to the existing Linux quality job's build dependencies so the
required Linux visual-ingest test can exercise real ffprobe, scene sampling and
frame decoding with a mock synthesizer. The test is not ignored and missing
binaries fail it. This adds no local execution permission and does not assert
Windows/macOS video behavior or a paid provider call.

W189 adds `capability-quality.yml`: one Ubuntu GitHub-hosted worker discovers
and verifies exactly the 18 focused capability-quality identities from their
source SHA bindings before running them (W188: 8, W189: 8, Doctor: 2). It is a
focused behavioral lane, not a replacement for full CI, preview, GUI, audio or
release validation. The lane grants no local execution permission.

W190/W191 use one grouped GitHub-hosted lane for the 15 exact behavior
identities after source-SHA discovery. It runs only after the optional W190
checkpoint layer compiles, preserves the one-worker bound, and is evidence only
for its selected identities; it neither replaces native/preview/full-CI gates
nor authorizes local execution.

Run `35717294010` compiled and passed all ten W190 identities before the first
W191 helper exposed a two-layer JSON-envelope lookup defect. The focused rerun
keeps the same exact-source discovery and one-worker boundary.

W190 adds a separate main-only `research-lifecycle.yml` Hosted lane for ten
source-SHA-bound lifecycle tests. It retains Rust 1.91, one Cargo worker,
serial exact discovery/execution, bounded runtime and retained receipts.
No local execution permission or Road/release acceptance is implied.

## Unreleased Windows preview

W182 adds a 15-minute default-feature `cargo check -p neoth --tests --locked --keep-going`
step to the existing Hosted CLI-reference job before its 25-minute public CLI
build. The job bound is 50 minutes, retaining nine minutes beyond the check,
build and one-minute reference export for setup and artifact upload. It keeps
one Cargo worker and detects shared test-code type failures without test-binary
linking or execution before expensive native dispatch. The a72 source produced
the same three library-test compiler errors in adapter, SSH and beta jobs,
demonstrating this gap in the previous binary-only check. This step is not native
behavior, optional-feature, GUI or release acceptance; those gates remain.
It grants no local execution permission. The first two Hosted checks exposed
three missing Council fixture fields and three missing database-path borrows in
W177 tests. These are repaired without changing assertions. `--keep-going` now
collects independent target failures within the same single-worker/time bounds;
it preserves the failing exit status and does not retry tests or compile jobs.

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

The preview job has a 360-minute outer bound. Its CLI, migration/relay and GUI
build steps have independent 90/15/90-minute bounds. Declared bounded steps total
332 minutes, including remote acceptance, leaving 28 minutes for setup and runner
overhead. Preview `35534407998` on `7909081e` built the CLI in 46 minutes and
completed migration/relay, then exhausted its 60-minute GUI bound. GUI warnings
were still emitted about 49 minutes into that step; the log contains no compiler
error. W119 grants 30 additional GitHub GUI minutes and the same increase to the
outer job bound while retaining one compiler worker and the existing reserve.
The interrupted cache and larger allowance do not prove a completed binary or
a measured warm-cache completion time. Compatible cache prefixes
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
exposes twenty-two callback test names to Nextest (W58/W73/W80 plus W116/W121/W122/
W126/W130/W138/W142/W149/W151, the two W153 fixtures, W155 citation consent and
W162 live throughput, W163 recall chips, W164 response feedback and the W167/W168
active daemon recall/throughput callbacks) and runs the selected fixture
directly from `main`; the coding controller fixture remains ordinary libtest.
Discovery must bind all twenty-two names to the custom binary and reject missing or
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

## W186 live-audio hosted lane

`live-audio.yml` is reusable from CI and can be manually dispatched with one
platform selector: `all` (the default), `linux`, `windows`, or `macos`. CI
calls `all`, so its one required job expands to Linux, Windows, and macOS.
The lane has one Cargo worker, a 120-minute Windows bound, and 90-minute Linux
and macOS bounds. It retains CI's `CARGO_INCREMENTAL=0` and zero debug-info
profiles for dev and test artifacts, preventing an optional tract build from
expanding hosted link/disk pressure. Linux installs `libasound2-dev` and
`pkg-config`; the native Linux desktop release build installs the same
dependencies with its GUI headers.

The lane builds and runs only the committed, exact `--lib` fixture identities
from `docs/verification/gold-wave186-live-audio-tests.json` with
`--features live-audio`. It first verifies every declared source SHA-256 and
rejects a missing, duplicate, or empty filter. It makes no physical microphone
capture and no provider request. Cargo output and the verified source-identity
manifest are always uploaded as a platform artifact, including on a compile or
fixture failure. The cache restores an OS/live-audio/lock-scoped complete key,
then compatible interrupted keys. A successful Cargo step alone writes the
immutable complete key. A failed Cargo step writes a source/run-suffixed
interrupted key, unless cancelled, so completed tract downloads and object
files are recoverable without being treated as a passing result.

`live-audio` stays optional for default and release-server/musl builds. Only
the native `release-desktop` capability bundle enables its pinned direct
dependencies, `cpal = 0.18.2` and `tract-onnx = 0.23.8`. A manual Linux-only
dispatch is suitable for an early hosted diagnostic; it does not replace the
full three-platform CI gate.

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
W184 (2026-09-22): source admission includes the default-off vault mirror and
its actual bare-remote/repair/retention/GUI fixtures. Preserve Hosted-only
execution: Preflight, early core test typecheck/CLI export, then native and GUI
acceptance on the exact admitted hashes. The retained-CWD helper has explicit
Unix and Windows tests; the new real GUI callback runs on Linux/macOS and is
registered in the 23-entry macOS custom harness. Prior full CI35674687864 stays
bound to a666a2c9; its two strict-Clippy diagnostics are fixed here. Do not infer
W184 runtime acceptance from earlier W183 compilation or the older Windows
preview. Road checkbox counts remain unchanged.

W184 Hosted follow-up (2026-09-22): eabc22a5 passed core test typechecking and
CLI compilation in 35675458308. Import its generated CLI reference and exact
Hosted formatting (35675458038), with the masked dummy restored only from the
frozen source. This is not native behavior acceptance. Old-source Windows/macOS
runs remain independently identified; no local execution or Road closure.

**W184 native compile follow-up (2026-09-22):** Windows and macOS jobs in
`35676411709` stopped at the same Slint callback/property name collision.
The status property is now `bc-vault-mirror-repair-state`; the action callback
is unchanged. The one formatting hunk from Preflight `35677253412` is imported.
Only those W184 deltas are admitted here; W185 remains separate working code.
Native compilation and behavior require rerun; no Road checkbox closes.

W186 adds the manual `silero-specialize.yml` Hosted lane: a 15-minute Ubuntu
job pins the ONNX tools, verifies the original model SHA-256 and Git blob, fixes
the production 16-kHz input contract through standard ORT basic optimization, and
compares probability plus recurrent state over 80 deterministic CPU windows.
Candidate publication requires finite outputs, valid probabilities, no remaining
If nodes and 1e-6 absolute/relative parity. It only exports a candidate and receipt;
Rust embedding, platform tests and microphone acceptance remain separate. It
permits no workstation execution.

W203 Hosted Preflight `35731939537` passed Rust formatting, then exposed two
stale preview-contract expectations for the old90-minute GUI ceiling. Both
contract suites now assert the intentional120-minute GUI limit while retaining
the360-minute outer bound, serial build, unchanged command and acceptance
checks. The contract correction needs a fresh Hosted Preflight; no Python or
other local validation ran. New grouped/core/preview runs on `a68442cb` remain
independent and are preserved.

**W203 second behavior follow-up (2026-09-22):** Grouped60 `35731968545` on
`a68442cb` executed all sixty identities:58 passed, two failed. W190/W191/
W192/W193/W194/W196/W197 now passed their complete selections. The remaining
n8n pin assertion now compares decoded Skill IDs against a proven nonempty
baseline; the Cron failure fixture now obstructs the mandatory bundled-resource
directory instead of supplying an unsigned manifest the loader correctly
excludes. Both focused changes passed independent static review; their new
Hosted execution is pending. Core/CLI `35731972532` passed on the same source
and exported the unchanged reference. `c82fc033` Preflight `35732446246` and
Code Quality `35732446029` passed. No Road checkbox changed.


**W203 durable Cron link / W202 format follow-up (2026-09-22):** Hosted
Grouped60 `35733913541` on `7f1070d9` executed all sixty exact identities;
59 passed. Its remaining failure exposed a production mismatch: the WAL
append receipt is a byte offset, while Cron persisted it as `fired_event_id`.
The shared event helper now preserves the generated header identity and returns
it only after durable append succeeds. Normal, failure and delivery consumers
share the corrected identity. The unchanged strict WAL-link test remains in
the selection, and independent source review passed. All sixty actual names
and source bindings were admitted from downloaded evidence. W202's first
Hosted Preflight exported formatting corrections for eight source files; the
exact patch, source HEAD and before/after Git blobs were verified on import.
No local formatter/test/compiler ran. Grouped83 and Core/CLI on `b704284d`
are still separate pending runs; Road checkboxes remain unchanged.


**W202 first Hosted behavior repair (2026-09-22):** Grouped83 `35735312775`
on `b704284d` executed every selected identity: 73 passed, ten failed. Eight
adoption paths stopped at the shared enqueue contract because the adapter
revision label was not canonical semver. Both producers now use the separate
adapter release `1.0.0`; artifact provenance remains `n8n-adoption-v1`, with
no n8n binary-version claim. Fresh-home status now returns unconfigured only
for two unchanged absent files after repeated pending-journal checks. The
remaining Cron link failure was already repaired in `2f189197`. Independent
source review passed, all 83 exact identities/source bindings were verified,
and no failing test was removed. Core test-target checking, public CLI build
and export `35735316615` passed; the hash-bound generated reference is imported
(SHA-256 `59b3d3c91f53d2b6cb9b3168377c22f5c0d64d8b8102a9436b91dfa0d1df0e4a`).
Three residual rustfmt hunks from Hosted `35736102874` are imported. Fresh
Hosted behavior/Preflight remain required; W204 remains uncommitted WIP and
Road counts remain unchanged. No local executable validation ran.
