# NEOTH 1.0 build and release cadence

This contract keeps the Road-to-Gold build wave fast without weakening the
evidence required for the public `v1.0.0` tag.

**W958 n8n startup-readiness repair (2026-09-24):** The second hosted image
canary36061161515 atd26ed44e passes five absence-regression tests and proves
owner/key200, bootstrap stop/absence and replacement runtime binding. Final
unauthenticated API validation fails; its ZIP and exact source are admitted
in `docs/verification/gold-wave957-n8n-bootstrap.json`. The pinned server can
answer before initialization; the canary now requires explicit readiness200
plus status=ok before strict401/403 and authenticated200/data checks. Two
focused regressions cover startup200 rejection and readiness-before-auth order.
Failure receipts gain only coarse statuses/runtime state, no payloads/logs.
Hosted rerun remains required. W952 product bootstrap is separate unreviewed
WIP; neither this feasibility lane nor source edits close GOLD-LF-002-09.
**W955 HTTP coverage and W953 canary repair (2026-09-24):** Root found eight
existing HTTP gate/permit/lifecycle tests absent from the focused selection;
all are now selected on Linux and Windows. Native1671 remains unchanged;
Group1446/Windows229 replace1438/221. Core050 passed production slim Clippy;
test-target typecheck found one MCP test-only Debug bound from expect_err.
The fixture now extracts Err without requiring Debug on the success payload,
retaining IFC-denial and zero-process-call assertions. Hosted rerun required.
Root admitted the failed first n8n image canary36060086745 at04b56b6e: owner
setup, key mint200 and encryption-config digest passed, but bootstrap removal
and final handoff are unproved. W953 corrects kind-specific Docker absence
matching and preserves primary failures through cleanup, with focused hosted
regressions. Artifact ZIP and both historical source hashes verified in
`docs/verification/gold-wave951-n8n-bootstrap.json`; rerun required, no product
bootstrap acceptance. Claude TASK019 covers the13 actual workflow imports.
**W949 isolated n8n image canary (2026-09-24):** W937 is published as a
manually dispatched main-only GitHub feasibility gate. A fresh labeled volume
and network-none bootstrap keep owner setup/key mint isolated; secrets enter
only via exec stdin. The exact bootstrap is stopped/removed before the final
loopback-published runtime uses the same volume. The canary checks preserved
encryption-key digest, real unauthenticated/authenticated API responses and
exact cleanup. W947 reviewed the main delta; Root additionally corrected Docker
Hub digest normalization and malformed/lost exec replies. This does not close
the product bootstrap, 13 imports or Paperless. Runtime evidence is pending.
Core36060005633 at050ebc6d is running; C7 and managed n8n remain open.
**W948 HTTP permit repair (2026-09-24):** Core36058966367 atf20c3c04 failed
strict production Clippy because the sealed transport supplied a no-op permit
verifier, leaving its binding fields unused. W946 now runs the existing exact
request/provenance verifier before pre-send and network execution, preserving
the independent sealed-request method/URL/body check. Root inspected the full
lifecycle and narrow diff; no warning suppression or authority removal.
Native1671/Group1438/Windows221 unchanged. Fresh hosted compile and behavioral
gates remain required; C7 and managed n8n stay open. No local execution.
**W945 C7 acceptance selection (2026-09-24):** Root checked the actual matrix:
only ActionKind-clearance was selected from the IFC kernel. Seven existing
lattice/release/redaction regressions are now added to Group; Windows selects
all eight. Current native1671/Group1438/Windows221. Exact single-file hosted
HackerNews formatting from Preflight36058966141 (artifact10833083981) is imported
with API ZIP, inner hashes, source and old/new blobs verified. Coref20 pending;
no feature closure and no local executable validation.
**W944 Hacker News consumer repair (2026-09-24):** Core413a found the two
remaining legacy external-HTTP calls in Hacker News and a missing direct Bytes
type dependency. W941 seals both requests with explicit15s timeout and the
existing versioned User-Agent; response status/limits/JSON stay before terminal.
The existing locked bytes1.11.1 gains only a direct neoth dependency edge.
W942 independently reviewed the delta. Seven existing real HN regressions are
now registered: native1664/Group1431/Windows213. Hosted gates pending; C7 open.
**W936 HTTP effect boundary and W932 MCP repair (2026-09-24):** The external
HTTP authorizer owns its sealed request and actual send. Citation validates
body/status/record before audit success;429 is failure before cooldown,404 is
valid NotFound, timeouts keep their original classification. W933 independently
reviewed all seven HTTP consumers. Core4386 exposed a missing CLI denial arm
and a budget-wrapper provenance downgrade; both are repaired with a real
wrapper regression. Ten new tests are registered: native1657/Group1424/Windows206.
Hosted formatting/compile/behavior pending; C7 remains open. No local execution.
**W935 n8n cleanup repair (2026-09-24):** Group1408 atc652 is Root-verified
1400PASS/8FAIL/0missing with251source/input bindings and3API ZIP digests.
Seven failures share a pre-prepare cleanup error; Windows190 independently
records183PASS/7FAIL for the same n8n cases. The publisher now carries an
explicit prepare-attempt witness: absent custody is allowed only before
prepare, while post-prepare ambiguity remains fail-closed. W931 static review
approved; one new missing-custody regression registered. Hosted rerun pending;
no roadmap closure. Current catalog: native1647/Group1414/Windows196.
**W927 MCP provenance implementation (2026-09-24):** Authenticated named
Telegram/Slack accounts can declare IFC source labels; opaque provenance is
bound to account/incarnation and a fresh inbound-turn nonce. Preflight owns it;
the actual MCP leaf rejects replacement, replay and compatibility downgrade.
Five registered regressions include a real successful Public tools/call.
W920 static review approved; hosted compile/behavior still pending. C7 remains
open. Group1413/Windows195/native1646 selected; HTTP and n8n repair separate.
**W912/W916/W921/W922 accepted evidence (2026-09-24):** Root admits all1383
Group fixtures and all142 Windows fixtures at0448daf4:0fail/0missing,248Linux
and31Windows historical source/input bindings,4API ZIP digests, every named
terminal and every Windows log hash verified. The exact26 C1a tests pass on
both platforms; all five published canary feature blobs still match, so
ADOPT31-C1a closes. Current C7 WIP is explicitly outside this admission.
Core36053242368 atc6527a5b passes all4gates; its source/hash-bound generated
CLI reference adds n8n install and is imported (W921). Managed n8n25newbehavior
cases remain unadmitted: Group1408run36054091216 failed the stale CLI-reference
fixture and seven n8n cleanup/cancellation cases (1400PASS/8FAIL). This exact
hosted CLI import repairs docgen; W926 repairs the n8n cleanup cause separately.
Windows190run36054094753 is still running.
Road1324/1075done/247open/2partial; raw249/pre-tag248. ADOPT31's67 numbered
rollups recount to37done/28unchecked/2partial (=30OPEN); the old31/36 split was
stale accounting, not six new feature completions. C1a is a mandatory child;
dashboard178OPEN. Evidence: gold-wave912-windows142.json, gold-wave916-group1383.json,
gold-wave921-core-cli.json and gold-wave922-c1a-acceptance.json in docs/verification.
No local executable validation ran. W911/W914 remain under separate review.
**W913/W915 hosted n8n follow-up (2026-09-24):** Root admitted exact hosted
six-file Rust formatting atf3e9f264 (ZIP10831143192, old/new Git blobs verified)
and published8d3817cd; its Preflight36052777903 passes. Core36052480246 stopped
before tests on two strict production diagnostics: private_bounds on the injected
managed installer and a dead probe-message helper. W915 narrows the helper to
integrations visibility and removes the unused method, preserving all guards.
The repaired source requires a fresh GitHub compile; no behavioral pass or Road
closure is inferred. Group1383/Windows142 on0448daf4 continue independently.
**W908/W910 managed n8n publication (2026-09-24):** Core36049730518 at4aae1d0f
passed strict slim Clippy, default-core test-target typecheck, CLI build and
reference export; Root verified the API ZIP digest, inner hashes and exact
source. The reference is unchanged. The completed owned CLI cache is a proven
exact hit; the 10m40s run is shorter than the previous 20m12s cache-fill run,
without attributing all timing variation to caching.
Managed n8n now has one durable job, a shared config/key publisher, private
CreateIntent/Bound/Ready custody, exact-ID compensation and absence tombstones
retained until credential rollback and durable terminal state. Uncertain
cleanup holds active jobs and capability leases; queued ambiguous intent writes
remain recoverable. Docker uses the local endpoint and durable HostConfig port
bindings. Only Ready yields a successful CLI result. W906/W910 independent
static reviews approved. Registered25 new cases plus23 existing adoption/custody
regressions on Windows; native1641, Group1408 and Windows190 await hosted runs.
Owner/API-key bootstrap,13 workflow imports and Paperless remain open; this is
not completion of GOLD-LF-002-09. No local executable validation ran.
B7 remains accepted. Repaired canary Group1383 run36051891177 and Windows142
run36051895109 at0448daf4 are running; C1a remains open pending exact terminals.
Claude TASK016 covers pinned owner/login/API-key middleware. C7 MCP producer-to-
effect work is separate WIP and excluded from this publication. Counts remain
Road1324/1074done/248open/2partial; raw250/pre-tag249; dashboard184open.
**W903 B7 accepted; W905 hosted formatting (2026-09-24):** Root verified
Windows142 atca4bf9e8:140PASS/2FAIL/0missing,31 historical source/input bindings,
142 individual log hashes and the API ZIP digest. Both failures are the canary
cases repaired in4aae1d0f. The new held-lock Windows watcher regression passes.
ADOPT31-B7 closes against40 exact Group1383 and38 exact Windows142 passing
terminals (30 in the document block plus8 earlier memory cases). All B7 feature
blobs remain identical to the admitted source; W894 found no consumer gap.
The real CLI produces a pending immutable proposal and explicit approval applies
Skill/Memory/Wiki effects with replay/ownership protection and metadata-only WAL.
B8's GUI remains separate and OPEN. C1a awaits behavior on the repaired source.
Root admitted the one-file hosted rustfmt patch from Preflight36049588541 using
source, API ZIP, inner hashes and old/new Git blobs. No local formatter ran.
W891's completed CLI cache is saved by36047680927;4aae Core36049730518 uses the
new checkpoint and passed all four core gates. Artifact/timing admission follows.
Road1324:1074done/248open/2partial; raw250/pre-tag249; ADOPT31 31done/36open;
dashboard184open. n8n/JobService WIP remains unpublished; W906 static review passed.
Evidence: docs/verification/gold-wave903-b7-acceptance.json,
gold-wave903-windows142.json and gold-wave905-hosted-format.json.

**W900/W901 canary integration repairs and W899 evidence (2026-09-24):**
Root admitted Group1383 run36047068548 atca4bf9e8:1378PASS/5FAIL/0missing,
248 source/input bindings and all three API ZIP digests verified. Four channel
failures share an unchanged strict preflight guard: Required-A canary insertion
changed typed items without refreshing the separate system text. W900 re-renders
that exact bundle, rejects a changed user prompt and updates the paired system;
the shared equality and final budget checks remain intact. W901 supplies the
teacher fixture's missing final model and asserts one actual authorized provider
invocation before quarantine. Production teacher behavior is unchanged.
W902 independently approved both frozen diffs. Hosted repair acceptance follows.
Core36045259775 passed all four gates; its generated CLI reference matches the
committed snapshot, with exact source/ZIP/inner hashes verified (W893).
Windows142 run36047072833 completed; its artifact admission is in progress.
W895 adds a durable recovery Hold and W897/Root continue the one-job n8n runtime
transaction; all n8n/JobService WIP is excluded from this publication. Claude
RESULT015 corrects export:workflow --output=- to a literal filename and confirms
that import can overwrite operator edits; bootstrap/import remain separate work.
Evidence: docs/verification/gold-wave899-group1383.json and gold-wave893-core-cli.json.
C1a/B7/B8 and Road1324:1073done/249open/2partial remain unchanged pending admission.

**W891 hosted validation and compile cache (2026-09-24):** Core36045259775
atca4bf9e8 passed strict slim production Clippy and default-feature core-test
typecheck; public CLI build/export remains in progress. Group1383 run36047068548
and Windows142 run36047072833 now validate the same source. B7/B8/C1a stay open
until their actual behavior and consumer criteria pass. macOS35983808777
attempt2 has built both desktop daemons and is building both GUIs.
The CLI-reference workflow now owns one completed Cargo checkpoint per OS,
Rust1.91 and lockfile, saved only after successful preceding gates and CLI build.
Measured prior runs restored the same old1.46GB partial cache; no speedup is
claimed before a completed cache warm-up and subsequent exact-hit measurement.
W892 is implementing n8n's one-job runtime custody transaction; its unfinished
source is excluded from this publication. Claude TASK014 requests pinned-source
bootstrap/import contracts. No local executable validation ran. Road counts
remain1324:1073done/249open/2partial; inventories1007/native1616/group1383.

**W888 document concurrency/Windows repair and C1a coverage (2026-09-24):**
W881 serializes the complete in-process document-note publication/reconciliation
path; W885 independent source review approved. Existing exact-byte/operator-edit
and cross-process create-only checks remain, and failed concurrent fixtures now
retain both error chains. The prior log does not identify a narrower syscall cause.
W886 fixes the demonstrated Windows watcher sharing violation: the held lock
intentionally denies DELETE sharing, so its commit fence now uses the existing
read-only no-follow regular-file identity probe. No lock sharing is relaxed.
A Windows-only real held-lock commit regression is added. Root admitted all115
historical Windows terminals:105PASS/10FAIL/0missing with26 source/input bindings;
all failures share that lock inspection error. New behavior awaits hosted rerun.
C1a gains the two missing detached-background cases from Claude RESULT012:
Native1616 +Win41/Linux55/mac55; Group1383; Windows142; canary selection26.
Core36044304900 passed the earlier type error and found one obsolete uncalled
Council wrapper under strict dead_code. W884 removes it; all live channel paths
keep the session-canary wrapper. Fresh Core validation follows; no Road closure.
Evidence: docs/verification/gold-wave878-windows115-terminals.json.

**W883/W878 hosted evidence (2026-09-24):** W880 is published at08881721.
Preflight36043416812 exported a three-file formatting-only patch. Root verified
the API ZIP digest, inner hashes, exact source and old/new Git blobs before
import; all raw-provider callsite fingerprints remain unchanged by formatting.
Group1357 run36041212636 atad2429e6 executed all1,357 named cases:1,356PASS,
1FAIL,0missing, with246 historical source/input bindings verified. The failure
is concurrent_identical_creators_preserve_one_exact_note; W881 is repairing the
actual note-publication race. B7 remains OPEN. All21 watcher group cases passed,
while B8's GUI scope remains OPEN. Canary Core36043417979 failed with one
E0308: a recovery String reached an Error-only opaque adapter. W884 wraps
that value at the caller; quarantine/logging behavior is unchanged. A new
hosted Core gate is required; no current compilation success is claimed.
C1a remains OPEN until its hosted behavioral acceptance. RESULT011 reports no
static leak defect on its moving snapshot; final W877 frozen review applies.
Claude TASK012 requests foreground/background C1a consumer and test mapping.
Evidence: docs/verification/gold-wave883-hosted-format.json and
 docs/verification/gold-wave878-group1357-terminals.json. No local runtime ran.

**W880 channel conversation canary publication (2026-09-24):** W869/W873/W876
wire an in-memory, bounded canonical-conversation canary into Required Block A,
direct/recovery/MCP/loop/Council provider leaves and the stream before previews.
Local-shadow and teacher completions are quarantined before cloud continuation
or correction-skill persistence; settled output is checked before archive and
prepared receipts, then checked again after PreEgress hooks. Post-mint provider
and Council errors are opaque. W877 final independent static review APPROVED.
The actual-handler regression reaches a finalized provider request, rejects a
whitespace-split echo before durable sinks and then verifies a clean next turn
with the same conversation token and exactly one prepared/egress receipt.
Twenty-four selected cases bring Native1614 (+Win40/Linux55/mac55), Group1381
and Windows139. The provider-callsite guard retains all five channel calls with
its changed stream-guard context explicitly rebound. Hosted validation remains
pending; C1a, B7 and B8 stay OPEN and all roadmap counts remain unchanged.
Claude ACK011 received; its final source review is still pending. GitHub-only
validation remains mandatory under the BSOD hold. See docs/gold-wave869-channel-canary.md.

**W874 watcher Core accepted (2026-09-24):** Core36039185385 at
aec43ce600e7dc277747bbea9dee2c17f9d68dc5 passed slim production Clippy,
default-feature core-test typecheck, CLI build and reference export.
Root verified artifact10825624412 against the GitHub ZIP digest, exact source
and inner SHA256 before importing the ten-line watcher command reference.
This proves the compiled source, not behavior or the in-progress C1a changes.
Windows115 run36040413126 is running at the same source. Group1357 follows
the bound CLI import. B7/B8 remain open pending behavior and GUI scope.
Evidence: docs/verification/gold-wave874-core-cli.json.
**W872 hosted watcher lint repair (2026-09-24):** W870 Core36038306012 at1f37a107
gets past the four compiler errors and fails only unnecessary_sort_by in the
bounded directory inventory. Use sort_by_key over the same OsString filename;
ordering and bounds are unchanged, and strict Clippy remains enabled.
No later typecheck/build/export ran in that failed workflow. Fresh hosted
core validation is required; Group1357/Windows115 and B7/B8 remain pending.
W869 channel canary code and W871 independent review proceed in parallel.
**W868 hosted watcher compiler repair (2026-09-24):** Core36037238201 at05392007
reported four compile errors before tests. The watcher now uses the existing
nonblocking std File::try_lock API, retains the inventory selection key before
an accepted-candidate binding shadows it, and computes the buffer bound before
its mutable borrow. No dependency, lock refusal, cursor or read-budget policy
was relaxed. Root inspected the minimal diff; a fresh hosted rerun is required.
Preflight36037741173 at4d3fdc03 passed all static contracts. Native behavior is
still pending. B7/B8 and counts stay unchanged. C1a's remaining channel-session
canary parity is the next independent implementation batch.
**W867 verified hosted formatting (2026-09-24):** W865 is published at05392007.
Preflight36037235185 exported artifact10825133257 after rustfmt-only drift.
Root verified the API ZIP digest, exact source, inner hashes and seven
old/new Git blobs before import; B7's two-call production fingerprint is
unchanged. Core36037238201 continues against05392007. Group1357 and Windows115
await the core/export result. No local formatter/compiler/runtime ran.
**W865 document watcher publication and admitted chapter access (2026-09-24):**
W856/W857/W861 add the default-off document discovery worker, bounded physical
inventory with persistent fair cursor, private revision notices, daily quota,
reload/cancellation fencing and actual proactive documents/dismiss-document
CLI consumers. No provider, extraction, distillation, staging or sending occurs.
Independent W859 static review is approved; hosted validation is pending.
W863 repairs the real B7 sanitizer contract: 16 lowercase xxh3-64 input fingerprint,
separate from 64-character source/candidate SHA256. W860's wrong audit-test
module path is corrected in both inventories; no test was removed.
Native1590 + Win40/Linux55/mac55; Group1357; Windows115 now selected.
B7 remains OPEN for executable acceptance; B8 remains OPEN including GUI toggle.
W862 Core36033068607@1599b33e passed slim Clippy, core-test typecheck and CLI
build/export; its verified CLI reference is imported. New watcher CLI needs
a fresh hosted export. W864 independently admits all15 B3 terminals from
Group36033072617@1599b33e, so B3 alone closes: ROAD1324/1073done/249open/2partial,
raw251/pre-tag250; ADOPT31 30done/37open; dashboard185open.
The parent Group1335 run failed later; no full-group or cross-OS pass is claimed.
Evidence: docs/verification/gold-wave862-core-cli.json,
docs/verification/gold-wave864-b3-terminals.json and
docs/gold-wave856-document-watcher.md. Local executable validation remains off.
**W858 exact hosted formatting (2026-09-24):** Preflight36032584867@149821ce
parsed the corrected fixture and produced the nine-file rustfmt receipt.
Root verified ZIP/inner digests plus every before/after Git blob before import.
The two-call document-staging guard is explicitly rebound to its formatted
five-line contexts; provider behavior is unchanged. Source manifest994,
Native1569+Windows39/Linux54/macOS54 and Group1335 remain the acceptance set.
Fresh Core/Group checks follow; no B3/B7 closure or local execution is claimed.
Evidence: docs/verification/gold-wave858-hosted-format.json.

**W855 hosted parser repair (2026-09-24):** W853 is published at8844dc72.
Preflight36032184376 found one test-only raw-string delimiter collision with
Markdown heading text in skills/document_staging.rs. The delimiter is corrected
without changing fixture bytes or production calls. Group/Core at8844 cannot
validate that source; fresh hosted checks are required. B3/B7 remain OPEN.

**W848-W853 document staging batch; W852 results (2026-09-24):**
Explicit --stage-route/--stage-target now connects exact staged preflight,
authorized candidate plus scored review, Pending Document proposal/notification,
and separate proactive accept to actual inactiveSkill, atomicMemory or create-only
userVaultNote consumers. Canonical source/input/candidate/route/target bindings
are revalidated at approval. Schema46 ledger prevents corroboration inflation;
ON DELETE SET NULL preserves actual OMI hard-purge and replay refusal. Existing
operator edits survive. Registered post-effect WAL is separate from the ledger;
audit failures are explicit and retry reconciles effects. Windows unsupported
directory sync is reported separately from real post-commit failures.
Independent static review approved;37portable+2Unix+1Windows fixtures added.
Native1569+Win39/Linux54/mac54;Group1335 selected. B7 stays OPEN pending hosted
compile/behavior. B6 GUI and B8 watcher remain separate. No local execution.
W852 Group1296@9877872e is ROOT-ADMITTED1295PASS/1FAIL with all237source/twoinput
bindings verified; CLI docgen now passes. Last B3 fixture falsely required its
marker at line start despite extractor line folding; corrected check preserves
the marker, all defanged line prefixes, exact rendered embedding and text-free
metadata. B3 remains OPEN. ROAD1072checked250open2partial unchanged.
See docs/gold-wave848-document-staging.md and
 docs/verification/gold-wave852-group1296.json.

**W845-W847 exact hosted results and chapter receipt repair (2026-09-24):**
Group1296run36023599487 at38230dc2 is ROOT-ADMITTED1294PASS/2FAIL after
three ZIP digests,237fixture/twoinput bindings and all individual terminals.
Failures: stale CLI reference and an extracted-chapter test that incorrectly
excluded the source marker from the intentional rendered_review field. W847
independent review confirms the existing contract; the test now checks text-free
chapter metadata AND a defanged operator-review marker. Production unchanged.
Core36022150044 at5f21bc06 passes slimClippy/testtargets/CLIbuild/export; Root
verified ZIP/source/inner SHA and imports its exact two changed help descriptions.
B3 remains open until the corrected connected test passes. B5/D7 stay accepted.
Claude ACK008/RESULT008 received; BulkText and same-SQLite-transaction replay
ledger selected for B7. TASK009 asks for filesystem custody/recovery specifics.
ROAD1072checked250open2partial;Group1296/native1532 unchanged. BSOD hold active.
Evidence: docs/verification/gold-wave845-group1296.json and
 docs/verification/gold-wave846-core-cli.json.

**W844 chapter fixture threshold correction (2026-09-24):**
Static tracing found that the real RTF extractor discards raw CR/LF, so the
initial W840 fixture's repeated safe-lines could fall below the large-document
threshold after extraction. The fixture now emits actual RTF paragraph controls
and contains enough non-whitespace text to cross200KiB independently of newline
normalization. Existing threshold, provenance and raw-text exclusion assertions
remain unchanged. No production behavior changed. Current5f21 hosted runs were
still active at diagnosis; no failure or pass is inferred from this correction.
ROAD1072checked250open2partial;Group1296/native1532 unchanged.

**W842 hosted extracted-chapter formatting (2026-09-24):**
Preflight36022122667 exported a two-file format patch for5f21bc06. Root verified
the archive, both inner digests, source HEAD and all old/new full Git blobs
before applying it. No local formatter ran. Group1296run36022144878 and
Core36022150044 retain the preceding behavioral source; no completion is inferred
from formatting. ROAD1072checked250open2partial stays unchanged.
Evidence: docs/verification/gold-wave842-hosted-format.json.

**W840 extracted-document chapters; W841 core acceptance (2026-09-24):**
Large PDF/Office/book text now enters bounded chapter discovery after the
existing extractor, through the shared /skill-from-doc review preparation.
Explicit selection sanitizes only the chosen UTF8 range; metadata receipts
retain original-source and extracted-text identities without raw text.
Extractor-reported truncation is refused so an early chapter cannot hide an
omitted tail. Small PDF/RTF reviews retain the full-review branch. Four new
fixtures cover actual admitted PDFs/RTFs, selected receipt custody and real
cappedRTF refusal; Group1296/native1532 are next. Independent source review
approved including Root's source-hash and nonvacuous text-exclusion checks.
B3 stays open until hosted behavior admission; B5 provider chapter invocation
is outside this provider-free review slice. Separately, Core36018697181 at033
passes productionClippy/testtargets/CLIbuild/export; Root verified archive,
source and inner CLI digest, which matches the existing reference exactly.
ROAD1072checked250open2partial remains. No local executable validation ran.
Evidence: docs/gold-wave840-extracted-chapters.md and
 docs/verification/gold-wave841-core-cli.json.

**W839 grouped acceptance and remaining document scope (2026-09-24):**
Group1292run36018692982 at033bccf0 passes all1292 fixtures. Root checked all
three archive digests,237fixture/twoinput bindings and every terminal. B5's
11reflexion plus six provider/preflight boundaries pass; D7's12 cases pass,
including the existing research terminal and zero outer-provider calls.
ADOPT31-B5/D7 close. B3's11raw-text cases and sanitizer compatibility also
pass, but its original adoption scope includes large extracted PDF/Office
text: that missing consumer remains open and is the next implementation.
B6 GUI/proactive, B7 staging and E2 AST code embeddings remain open. Claude's
RESULT007 arrived and was read; TASK008 now requests actual vault custody and
same-transaction memory deduplication. Preparation is not delivery/acceptance.
ROAD1324/1072checked250open2partial;raw252/pre-tag251;ADOPT38open29done;
dashboard186open;WS-LF38done80open. No local executable validation ran.
Evidence: docs/verification/gold-wave839-group1292.json.

**W838 hosted test import repair (2026-09-24):**
Group1292run36017807925 at7fdfb0a4 stopped at test compilation: three new
preflight fixtures imported ProviderKind through a private config import.
They now use the existing public cli::init re-export. Production Clippy passed
in Core36017801960; no behavior ran in the failed grouped attempt. Preflight
3835772c is green. Counts1070checked252open2partial remain; hosted rerun next.

**W836 hosted formatting (2026-09-24):**
Root imported the three-file Rust formatting patch from Preflight36017803481
at7fdfb0a4 only after verifying artifact10814884303 ZIP, both inner digests,
source HEAD and each old/new full Git blob. No local formatter ran. Core
36017801960 and Group1292run36017807925 cover the preceding behavioral source;
those gates remain active. ROAD1070checked252open2partial stays unchanged.
Evidence: docs/verification/gold-wave836-hosted-format.json.

**W835 document boundary repairs and W832 replay acceptance (2026-09-24):**
Root verified all three Group36015215923 archives at095d10f0,237fixture/twoinput
bindings and every terminal:1282PASS/3FAIL. D5's12 cases all pass, including the
production HOME/skills repair, so ADOPT31-D5 closes. ADOPT31-B11 also closes:
18 existing catalog and actual session-consumer terminals pass. The shared,
authority-bound composer already provides the logical-session injection;
adding it to a daemon-boot hook would duplicate the wrong lifecycle boundary.
D7 is11/12; B3 is10/11;
B5's11 cases pass but its independent review found two real preflight defects.
W831 now shares the actual utility endpoint/profile identity, keeps custom
prices unknown, and refuses unbounded Claude CLI before emitting a finite
receipt. W833 derives chapter ranges from the64KiB sanitizer cap instead of
256KiB; the original large CLI source remains unchanged. W834 supplies the
counting test provider's required default model without weakening terminal or
zero-call assertions. The raw-callsite inventory records the two reviewed,
cost-authorized document calls. Seven boundary cases join Group1292; executable
repair validation remains hosted-only. ROAD1070checked252open2partial;
raw254/pre-tag253;ADOPT40open27done;dashboard188open. B6 GUI and B7 remain open.
Evidence: docs/verification/gold-wave832-group1285.json.

**W827 grouped source binding repair (2026-09-24):**
Group1285 run36014123642 atbd81ffde stopped before compilation or fixtures:
seven platform-specific document tests still referenced the pre-format source
hash. The matrix also held CRLF working-copy manifest bytes rather than the
committed LF bytes. Root rebound those records and the manifest using verified
Git blobs and the existing staged-source helper. No product behavior changed;
no test result or roadmap criterion closes from this repair. Preflightbd81
passes. Hosted Group1285 rerun is next; counts1068checked254open2partial remain.
Evidence: docs/verification/gold-wave827-source-binding-repair.json.

**W826 document hosted core and CLI reference (2026-09-24):**
Core36012497363 ate787f32d passes production Clippy, all core test-target
compilation, CLI build and export. Root verified artifact10814041199 ZIP, source
and inner CLI digest before importing docs/cli-commands.md. The subsequent
beb4983f source delta is the already verified hosted formatting only. Group1285
is next for actual D5/D7/B3/B5 behaviors. W819 independent review remains pending;
B6 GUI/proactive and B7 staging remain open. Counts1068checked254open2partial.
Evidence: docs/verification/gold-wave826-document-core-cli.json.

**W825 hosted document formatting (2026-09-24):**
Root verified and imported artifact10812454433 from Preflight36012495980:
ZIP, inner digests, source e787f32d and both full-index before/after blobs match.
Production Clippy36012497363 passes; testtarget/CLI/behavior remain pending.
Counts1068checked254open2partial unchanged. No local formatter or compiler.
Evidence: docs/verification/gold-wave825-document-hosted-format.json.

**W819 explicit document distillation and scored review (2026-09-24):**
An opt-in --distill-doc command requires a0..100 minimum score, emits/flushed
preflight before provider resolution, then uses existing consent/cost authority
for one candidate call and one scored review. Unknown prices remain null;
provider errors/refusals/truncation and malformed/low scores cannot stage.
No skill/memory/wiki installation or proposal is performed. B1/B3 previews stay
provider-free. Eleven tests cover ordering, bounds, prices and refusal. Source
is implemented and Root-inspected; independent review and hosted gates remain
pending. B6 GUI/proactive consumers remain open. Group1285/native1521 planned.
W823 imports two exact hosted formatting edits for replay/D7; source/digests
verified. Core676 production Clippy and test-target typecheck pass; CLI building.
Counts1068checked254open2partial unchanged. No local executable validation.
See docs/gold-wave819-document-reflexion.md.

**W817/W822 video acceptance and replay routing repair (2026-09-24):**
Root admitted Group1251 at2b38:1250PASS/1FAIL with236source/twoinput bindings.
F4's22 cases all pass; its pinned installer, wizard call, caption-first consent
and audited fallback satisfy the original row. F4 closes independently. D5
has11PASS/1FAIL: the production adapter passed HOME to a Skill-directory API.
Root corrects that binding to HOME/skills while retaining the actual usage home
and the test's original public-home argument and authority/body assertions.
Core7bea passes production Clippy; five D7 test-helper scope errors are repaired
with a shared counting provider. Preflight7bea passes. Hosted rerun pending.
ROAD1324/1068checked254open2partial;256raw/255pre-tag;ADOPT42open25done;
dashboard190open. No local executable checks. B5/B6 implementation continues.
Evidence: docs/verification/gold-wave817-group1251.json.

**W816/W818 hosted format and chapter handle repair (2026-09-24):**
Root admitted the five-file hosted format patch from run36006059637/artifact
10810199507 after checking archive, inner digest, source and old/new Git blobs.
Core36006062602 found two E0308 handle mismatches in the new chapter path.
The retained snapshot and verifier now consistently use cap_std::fs::File,
preserving the opened no-follow capability and all source revalidation.
Hosted rerun is pending; D7/B3 remain OPEN. Group1251 finished with a failure;
its individual D5/F4 terminals are being admitted separately. No local build,
formatter or tests ran. Counts remain1067checked255open2partial.
Evidence: docs/verification/gold-wave816-chapter-compile-repair.json.

**W805/W806 routing and bounded text chapters (2026-09-24):**
D7 adds explicit workflow/changing-facts inputs and a default-off route policy.
It reuses the real research terminal and existing configured provider builder,
keeps human handoff before provider dispatch, refuses D7 in Incognito, and
excludes these requests from daemon forwarding. Independent review is clear;
12cases cover evidence, consumers, role selection and admission. The no-key
research test fails instead of silently skipping on a live-search environment.
B3 adds explicit large-UTF8-text chapter discovery and selection with retained
source custody,64MiB source/256KiB range/4096range limits, UTF8-safe coverage,
mutation refusal and metadata-only JSON plus defanged review.11cases include
actual CLI route functions. PDF/Office remain on their existing full extractor;
no binary byte-range capability is claimed. Independent review is clear.
Both remain OPEN pending hosted compile/format/behavior and scope acceptance.
Group1251run36005780610 at2b38a54a tests the preceding D5/F4 source; next catalog
is1274/native1510. Counts remain1067checked255open2partial; no local executables.
See docs/gold-wave805-verifiability-routing.md and
 docs/gold-wave806-document-chapters.md.

**W812 replay/video hosted core (2026-09-24):**
Core36004158300 atc2179922 passes test-target typecheck, CLI build and export.
Root verified artifact10810630207 ZIP/source/innerdigest and imports its real
CLI reference. ProductionClippy passed earlier at4a438c95; only the retained
fixture snapshot changed subsequently. Group1251 is next for34newD5/F4 cases.
D5/F4 remain OPEN. No local executable checks. Counts1067checked255open2partial.
Evidence: docs/verification/gold-wave812-replay-video-core-cli.json.

**W801/W802 hosted format and compile repair (2026-09-24):**
Preflight36000967795 at063811ea reported formatting only. Root verified its
artifact ZIP, inner digests, source head and all11 full-index old blobs before
importing the hosted patch. Core36000986600 then identified parameter doc
comments, an Option/Result residual and two unused declarations; these exact
sites are repaired without weakening assertions. D5/F4 remain OPEN pending
hosted compilation and their34 selected behavior cases. No local executable
checks ran. Counts remain1067checked255open2partial;Group1251/native1487.
Hosted follow-up:Preflight36002408201 at5a870310 passes, including10/10
replay-witness Python tests. Core83297 found one additional Clippy string-
replacement style issue; its exact fix preserves Markdown output. Rerun pending.
Core36002877760 at4a438c95 passes production Clippy. Its testtarget found one
E0716 in the new replay-skill fixture; the expected snapshot is now retained
through the unchanged assertion. Only testtargets/CLI are rerun for this fix.
Evidence: docs/verification/gold-wave801-hosted-format-and-compile-repair.json.

**W799/W800 video URL and real workflow replay (2026-09-24):**
F4 now connects explicit ingest --video-url, caption-first processing and
separately bound/audited media fallback to the existing extractor. The real
wizard installs the digest-pinned standalone yt-dlp asset for supported
Windows/Linux/macOS targets. Direct native probe, streamed installer limits,
and aggregate staging supervision are source-reviewed;22tests are selected.
D5 adds eval capture/run while preserving legacy suites. It runs the real
prepared chat/provider path with isolated conversation/WAL/workspace and real
operator provider-consent/cost accounting. A typed completed body and accepted
terminal alone feed contains-v1. Reports bind actual selected skill snapshots
and the full secret-free config digest.12tests are selected; independent
review passes. The optional release consumer keeps raw workload data local
and accepts only a content-free manually submitted witness on GitHub.
Both criteria remain OPEN pending hosted compile/CLI export and behavior.
Next lane:Group1251/native1487 plus Win38/Linux52/mac52;GUI159 unchanged.
Road1067done255open2partial is unchanged. No local executable checks ran.
See docs/gold-wave787-workflow-replay.md, docs/gold-wave790-video-url.md and
 docs/gold-wave793-workflow-replay-gate.md.

**W797 specialist-advisor acceptance (2026-09-24):**
The corrected Group1217 run35997962184 at f7cc563b passed1217/1217.
Root independently verified all three ZIP digests,231fixture-source and two
input bindings, and all actual terminals. All13 D6 tests pass, covering the
explicit checklist, honest cost/volume evidence, the real G02 producer,
durable cooldown/restart and malformed-input isolation. ADOPT31-D6 closes.
The preceding f7cc Preflight requested only assertion layout; its exact shown
formatting is incorporated without a local formatter. D5/F4 remain under
focused source review and have not been admitted. No local executable checks.
Road1324/1067checked/255open/2partial;257raw/256pre-tag;WS-LF38done80open.
WS-ADOPT31 now43open24done; dashboard191open.
Evidence: docs/verification/gold-wave797-specialist-advisor.json.

**W791/W792 hosted results and queue fixture (2026-09-24):**
Root verified six ZIP digests and every individual terminal. GUI159 at
272105e8 passed159/159 with29source/input bindings, including W153's unchanged
visible-reply assertion. Group1217 at efad6d9b passed1216/1217 with231fixture
source plus2input bindings. Its sole failure was the D6 invalid-assessment
fixture expecting no queue file; the intended reconciliation persists that
file. W792 instead proves no D6 item and preservation of an independent G02
item. D6 stays open until its corrected test runs on GitHub. Preflight efad
35995374333 passed, and Corea01's four selected gates/export were admitted
with unchanged CLI reference; workspace Clippy was skipped. D5 replay and
F4 video URL remain in implementation. No local executable validation.
Road1324/1066checked/256open/2partial;258raw/257pre-tag;WS-LF38done80open.
Receipts: gold-wave791-hosted-results.json and gold-wave789-core-advisor.json.

**W788 Preflight allowlist alignment (2026-09-24):** the GUI lint step itself
passed, but the offline cadence contract correctly rejected its unlisted
command block. The exact four-line noncompiling block is now explicitly
allowlisted; existing strict command equality remains intact. Hosted rerun
is pending. Road1066done256open2partial is unchanged.

**W783/W784 grouped and GUI-source acceptance (2026-09-24):**
Root verified all three Group1204 artifact digests,229fixture-source plus two
input bindings and1204/1204actualPASS at4ed780a6. C10's11, B9's5, D1's8 and
D4's9 selected tests pass. G6's embedded gui_copy_lint and owned triggers are
covered by the same whole-bundled parse/count/ownership/router tests; no live
model-quality or rendered-GUI claim is added. Those five criteria close.
G2/G5 close on the successful hosted token/motion self-tests and production
source scan at a01c9608. The named GUI gate wrapper now invokes those checks.
Preflight's separate Rustfmt failure is being repaired from its exact artifact.
D6 source is published but remains open pending its13 hosted test results.
Road1324/1066checked/256open/2partial;258raw/257pre-tag;WS-LF38done80open.
Receipts: gold-wave783-group1204.json and gold-wave784-gui-lint.json.

**W775/W779-W782 specialist advice and design-document batch (2026-09-24):**
D6 now consumes the real 30-day usage rollup and a strictly bounded local
schema-v1 operator assessment. Unknown facts, provider completion and the
unclassified bucket cannot qualify a candidate. G02 queues useful advice;
queue-owned atomic cooldown survives drain/restart, stale own recommendations
are reconciled, and bad input leaves independent profile surfacing intact.
Independent static review completed; 13 selected behavioral/regression tests
join Group1217/native1453. D6 remains open pending hosted results.
G1/G3/G4 close on their original document/process criteria. G2's named wrapper
now calls the existing self-test and source lint; Preflight runs those same
cheap checks on GitHub. G2/G5 await that run; G6 awaits the selected bundled
parse/router tests in running Group1204. No Slint files changed.
Road1324/1059checked/263open/2partial;265raw/264pre-tag;WS-LF38done80open.

**W774 generated CLI reference (2026-09-24):** Core235 run35991244554
passed slim production Clippy, core test-target typecheck, CLI build and CLI
export. Optional workspace Clippy was not requested and was skipped. Root
verified/imported artifact10805320688 (exact235source;ZIP80bc9e39…206ca,
CLIb2a52841…76bbae). The reference now includes --rubric-config. Group1204
can execute the four newly selected criteria; no behavior pass is claimed yet.

**W770-W773 document and workflow-cost acceptance (2026-09-24):**
Root admitted GUI35986281164 at5e9:159executed,158PASS1FAIL,29source/input
bindings; Windows35988664776 atc6ef:55/55PASS,15bindings. All ten D2 GUI
checks and all five new Windows document/creator checks pass. Together with
Group1171, the original B1/B4/D2 criteria close independently of W153's missing
reply failure. Its authenticated feedback target is valid; no speculative
removal is retained. W773 adds safe terminal categories for a hosted rerun.
W772 imports the exact three-file235 hosted formatter output; CodeQL235 passes.
Road1324/1056checked/266open/2partial;268raw/267pre-tag;WS-LF38done80open.
Core235 CLI export precedes Group1204. No local executable validation.
Evidence: docs/verification/gold-wave770-gui-windows.json and gold-wave772-hosted-format.json.

**W757-W767 offline rubric and focused acceptance (2026-09-24):**
The real offline evaluator consumes explicit expected/observed labels and
operator-configured false-alarm/missed-violation multipliers. Final verdicts
follow label agreement; even zero-weight mistakes fail. Ambiguous/missing
configuration, verifier errors and step-cap skips remain unclassified errors.
Reports carry effective weights and dimensionless error units. Independent
review passes; new hosted compile/CLI/behavior evidence is pending.
Root independently admitted ddb Group1171:1171PASS0FAIL,221sources+2inputs.
F1/F2/F3,D3,B2 close on their own passing criteria. C9's comment-only crosswalk
closes from pinned authoritative upstream section4.1, correcting a stale source
citation without renaming WAL fields. B1/B4 Windows and D2 GUI remain pending.
Next selection:Group1204/native1440+Win38/Linux52/macOS52, including existing
C10 WorkerContract,B9 Fabric and D1 training-export consumers plus D4 regression.
Road1324/1053checked/269open/2partial;271raw/270pre-tag;WS-LF38done80open.
See docs/gold-wave767-offline-rubric-and-acceptance.md and the W764 receipt.

**W755 grouped selection guard repair (2026-09-24):**
The c6ef Group dispatch stopped before compilation because a second shell
count guard still expected1149 while the bound catalogue correctly held1171.
The guard now also requires1171; no test outcome or product failure is inferred.
c6ef Preflight and Code Quality passed; Core and Windows55 continue.
Road counts stay1047done275open2partial. Group-only rerun follows this repair.

**W747-W750 catalogue acceptance and document review batch (2026-09-24):**
Root verified Group35986277953 at5e9:1120 actual PASS, zero FAIL,29 unrun,
with217 fixture-source and two input bindings. The next selector lost its first
character after the real ffmpeg fixture inherited the catalogue stdin. Discovery
and test subprocesses now receive /dev/null; full rerun remains pending.
H1 closes on its two exact catalogue/roster passes. Slack import/queue and the
prior WebChat fixes passed their selected tests. No whole-job success is claimed.
B2 now renders a substantive seven-section, source-grounded operator prompt
beside defanged document text, preserving provider-free review. Independent
review passed. Existing B1/B4 document/scanner/creator checks are newly selected:
Group1171, native1416 plus Windows38/Linux51/macOS51; Windows lane55.
B1/B2/B4 and F1-F3/D2/D3 remain open pending their relevant actual results.
Road1324/1047checked/275open/2partial;277raw/276pre-tag;WS-LF38done80open.
Evidence: docs/verification/gold-wave747-group1149.json. No local executables.

**W738-W743 custody results and focused adoption qualification (2026-09-24):**
Custody35984512675 atd1e51dc5 passed all44 tests and Clippy, including the three
new Slack source-selection cases. Its only failed step was formatting; Root
verified/imported the exact three-file Preflight formatter artifact. F1/F2/F3
are already implemented; six existing scene/decode, MAD-boundary/dedup and
sparse-keyframe tests now join the hosted selection, including real ffmpeg on
Linux. Twenty-four existing workflow-cost/prompt-tax checks also join the
selection. Ten existing GUI workflow-cost checks are also selected: GUI159Linux/
155macOS, with no Slint/source changes. Native1398/Group1149; no Road closure.
Core35984509622 atd1e passed all four gates; W743 imports its exact new CLI
reference. Group1149 and GUI159 can now validate the selected source.
See docs/verification/gold-wave738-custody.json and gold-wave738-hosted-format.json.

**W731-W736 OpenClaw Slack import and queue admission (2026-09-24):**
The CLI selects one schema-backed OpenClaw Slack account and requires an
explicit target account and allowed member. Only direct bot/app tokens from
an accounts-only Slack container are accepted; unsupported source policy is
rejected. Existing prepare/auth.test/team-bound CAS/reload logic is shared;
the complete source set is rechecked after probe and before commit. Nine new
custody/CLI tests plus six existing Telegram and two H1 catalogue tests bring
native1392/Group1119 (three custody tests run in the separate package lane).
Independent source review passes; executable validation remains pending.
105f47f8 Core passed all four gates. Root admitted Group1104:1100PASS4FAIL,
207source bindings plus two inputs. All five WebChat rejoin tests pass. W735
repairs the production Telegram-only queue gate that blocked three Slack cases,
with one new crossed-channel regression; its independent review passes.
The fourth failure is the stale CLI reference. The exact105f export is imported;
the new import-command export precedes the next Group.
macOS package35983808777 runs at105f47f8. H1 is still open until its two narrow
catalogue tests pass. Road1324/1046checked/276open/2partial; no local runtime.
See docs/gold-wave734-openclaw-slack-import.md.

**W726/W728 hosted format and fixture compilation repair (2026-09-24):**
Root imported the exact ten-file formatter artifact for2871b03a after ZIP,
checksum and old/new blob verification. Group1104 run35981343867 stopped at
five compiler diagnostics in two test helpers; no fixture executed. The Slack
scripted adapter now converts String errors explicitly, and the provenance
fixture serializes JSONL directly into bytes. Production behavior and test
assertions stay intact; new hosted execution is pending. Prior40d56291 Core
run35979624562 passed Clippy/typecheck/CLI build/export; its exact reference
is unchanged. Native1374/Group1104 and Road1324/1046checked/276open/2partial
remain unchanged. No local executable validation. See W726 format/Core receipts
and docs/verification/gold-wave728-group1104-compile-repair.json.

**W719/W723-W725 WebChat rejoin and named Slack app DMs (2026-09-24):**
WebChat resumes only durable WebChat/default sessions through authenticated
same-user RPC; fresh cookies restore saved history without old turn authority.
Incognito identity stays absent; ledger reads are bounded per record. Slack
named-account delivery now uses its freshly verified binding and allowed member,
then opens/posts to the actual app DM inside the one-shot Armed transport seam.
Fourteen new regressions yield native1374/Group1104; independent source review
passes, new execution pending. Root admits40d56291 Group1090:1089PASS1FAIL,
205sources+2inputs, all nine W710/W712 cases PASS. The remaining recovery fixture
now sets the intended Full autonomy; assertions unchanged. macOS limits/cache
were adjusted after measured hosted timeouts, without weakening package checks.
Road1324/1046checked/276open/2partial; WS-LF38done80open. No local runtime.
See docs/gold-wave725-webchat-rejoin-and-slack-dm.md and its Group1090 receipt.
**W722 hosted-format and Slack gate correction (2026-09-24):**
Main99a0f650 contains W710/W712-W718. Preflight35978618380 supplied three
exact formatter rewrites; Root verified ZIP, checksums and old/new Git blobs
before import. Core35978644752 stopped at collapsible_if in the known-team
probe; the equivalent guard is flattened, preserving every mismatch check.
The new reload/health regression selector now names its actual
channel_reconcile_tests module. Native1360/Group1090 counts are unchanged;
new hosted execution is pending. Quality35978616514 passed. No Road closure
or local executable validation. See docs/verification/gold-wave722-hosted-format.json.
**W712-W718 Slack workspace binding and hosted results (2026-09-24):**
Claude RESULT-002's observed team_id now survives candidate auth.test into the
paired-file CAS commit. Same known workspace keeps an existing incarnation;
new/unknown/cross-team or missing-incarnation state gets fresh authority. Known
account tests refuse mismatched or absent observed teams; legacy unknown remains
compatible. Reload and health bind team identity; no named proactive DM claim.
Seven new Slack cases plus W710's two extend native1360/Group1090. Source review
passes; new execution is pending. W715 admits59e2d5eb1081executed1079PASS2FAIL,
204sources+2inputs; all WebChat/CUA cases pass. W716 repairs the Cron self-heal
alert distinction and canonical WAL test path. W717 Core at59e2d5eb passes all
four gates; exact CLI reference unchanged. Road1324/1046checked/276open/2partial;
WS-LF38done80open. No local executables. See docs/gold-wave718-slack-workspace-and-hosted-evidence.md.
**W710 WebChat CLI onboarding (2026-09-24):**
Interactive init now gives the enable/serve/mint browser setup sequence.
Onboarding JSON/table project disabled or configured_needs_serve from Companion
configuration; live readiness remains in neoth status. Existing provider/channel
readiness and loader errors are preserved. Two real config/snapshot/JSON/render
regressions extend native1353/Group1083. Independent source review passes; new
execution remains pending. W70859e2d5eb Preflight35973509291 passes; its Core and
Group1081 runs retain their own source binding. No Road closure or local runtime.
Road1324/1046checked/276open/2partial;WS-LF38done80open.
See docs/gold-wave710-webchat-onboarding.md.
**W707/W708 hosted formatting and WebChat fixture compile repair (2026-09-24):**
Root verified and imported nine exact formatter rewrites from Preflight35972375977
at3ed5622b, including ZIP, inner checksums and old/new Gitblobs. Group1081
run35972374505 stopped before any test: two E0599 errors in the new real-listener
fixture called unwrap twice on a JoinHandle<()> result. Both awaits now match
spawn_for_home's actual return type; all listener/child assertions remain intact.
No tests passed or failed in that run;1081 were not started. Hosted rerun pending.
Road remains1324/1046checked/276open/2partial;WS-LF38done80open. No local executables.
See docs/verification/gold-wave707-hosted-format.json and gold-wave708-group1081-compile-repair.json.
**W700-W706 WebChat custody/readiness and CUA compatibility (2026-09-24):**
The sealed browser session now reaches chat preparation before hindsight, WAL,
recall and actual transcript writes. Real-producer regression covers separate
A/B persisted pairs and global Incognito absence. Reconnect exchanges the stored
grant before status, clears completed ordinary turns and retains Incognito replay.
Status uses authenticated read-only RPC with real listener/child-client coverage.
Claude R04's exact upstream contract29 is independently verified: seven equivalent
CUA verbs join legacy11; default19other verbs stay denied. Explicit enable migrates
only the recognized old default; Doctor uses actual configured policy and aliases.
Independent source review passes;12new selected cases yield native1351/Group1081.
PriorCore35969533176 at18ff87aa passes Clippy/typecheck/CLIbuild/export; exactCLI
4445f7b2 imported249367bytes. New source execution remains pending on GitHub.
Road1324/1046checked/276open/2partial;WS-LF38done80open. No local executables.
See docs/gold-wave706-webchat-custody-and-cua.md and W702/W704 receipts.

**W691-W696 authenticated WebChat and fixture repairs (2026-09-24):**
A one-use same-user RPC handoff opens the existing loopback listener's WebChat.
Server-owned session/request IDs and capabilities bind consent, idempotent start,
replay and cancel to the existing runtime; native GUI authority remains separate.
Bounded saved transcript, reconnect and safe text rendering have nine new native
and seven separate Chromium fixtures. Static review passed; Root also repaired
replay mutability and an in-flight reconnect race. Browser35969536101 at18ff87aa
now passes7/7; Root verified3sourcebindings and all terminals. W698 imports the
exact nine-file hosted formatter patch. Rust Core/CLI verification still runs.
Group1060 run35966268023 atdb1d9758 is Root-admitted1054PASS6FAIL0missing with
201source/inputbindings. Six fixture repairs preserve all original assertions.
Portable native1339/Group1069; regenerate the CLI reference before grouped tests.
Claude RESULT-001 is integrated; TASK-002 pending and new EXTRA research triaged.
Road stays1324/1046checked/276open/2partial;WS-LF38done80open. No local executables.
See docs/gold-wave691-webchat-and-group-repair.md and W689/W692 receipts.

**W684-W686 routing repair and hosted acceptance (2026-09-24):**
Persisted account-only Slack items retain their physical channel and settle as
configuration errors before Telegram authority; active public or credential
Slack maps block damaged legacy scalar egress. Two focused regressions extend
portable native1330/Group1060. Independent static review passed; new tests pending.
Windows5035964379685 at796d34ed is Root-admitted50PASS0FAIL0missing:58hashes,
11sourcebindings,2inputs and all50 exact terminals verified. Paperless38-40 and
retained-DELETE namespace49-50 pass. Actual managed Docker remains separate.
Core35964376655 passes slimClippy, testtypecheck and CLIbuild/export; generated
CLI58079e3e is imported byte-exact before grouped dispatch. W683 carries four
schema2 routing passes without closing an incomplete account-wide criterion.
Road remains1324/1046checked/276open/2partial;WS-LF38done80open. No local executables.
See docs/gold-wave686-routing-and-hosted-acceptance.md and W685/W686 receipts.

**W681 hosted lifecycle formatting (2026-09-24):** Imported the exact three-file
formatter patch from Preflight35964352196 at796d34ed. ZIP, patch checksum, source
receipt and all old/new Gitblobs match. Core and Windows50 continue their original
source-bound runs; Group1058 waits for the regenerated CLI reference because the
command surface changed. No local formatter or new Road closure.

**W675/W676/W679-W680 named Slack account lifecycle (2026-09-24):**
File-backed Slack add/rotate/remove/migrate/test now uses explicit account IDs,
strict private stdin tokens and the existing prepared-pair transaction. The
exact candidate is auth.test-probed then CAS-committed; rotation selects policy
inside the lock. Failed probes/drift preserve files. Retirement removes typed
Slack IDs from both lossless overlays while preserving sibling/unknown fields;
re-add mints a new incarnation. Keychain writes reject before mutation.
CLI map tests require explicit account selection; flat mutations reject maps.
Registry now exposes named-account support for Telegram and Slack. Proactive
Slack routing, keychain custody and surface parity remain separate P1-16 work.
Fourteen new regressions plus two existing contracts extend native1328/Group1058.
Hosted Core35963133128 found an unused superseded default-account helper;
Group35963135066 and Windows5035963137255 compiled0fixtures because an opaque
BindingTag assertion required Debug. Exact dead-code removal and boolean
inequality preserve behavior; new hosted verification is pending.
Independent static review passed. Road stays1324/1046done/276open/2partial;
WS-LF38done80open. No local executable validation. See W680 lifecycle document.

**W678 hosted reload tuple correction (2026-09-24):** Core35962545321 reports
three E0308 errors: Slack added an eighth reload-candidate tuple element while
three borrowed destructures still expected seven. All three now retain the
new field position; retry and debounce semantics stay unchanged. Hosted
compilation/behavior pending; no Road closure or local executable checks.

**W677 hosted formatting (2026-09-24):** Preflight35962290710 parses the repaired
source and supplies a twelve-file rustfmt patch. ZIP, source receipt, patch
checksum and every old/new Gitblob verified; imported byte-exact. Core/Group1042/
Windows50 will rerun this source. Road counts unchanged; no local formatter.

**W674 hosted syntax correction (2026-09-24):** Preflight35962137807 at5e36a39b
found one extra closing brace in the new Slack startup block. The exact single
delimiter is removed; hosted format and native behavior are still pending.
No local executable validation and no additional Road closure.

**W664-W673 Slack accounts, source-bound GUI acceptance and targeted repairs (2026-09-24):**
Named Slack accounts now have exact policy/secret pairing, duplicate-map rejection,
separate startup/reload/health identities, secret-free status, isolated ingress,
and authenticated live reply/WAL provenance. Seventeen focused portable tests
exercise the production factories, including framed-token collision rejection.
CLI account mutation and proactive Slack routes remain separate P1-16 work.
Windows48run35959097476 is Root-admitted45PASS3FAIL; final namespace validation
now uses the retained stage identity and DELETE-sharing probe. Two new Windows
regressions keep both retained-handle success and wrong-generation rejection.
Group1025run35959735629 completed1015 exact tests:1014PASS1FAIL; the next discovery
aborted on a wrong Cron module path and nine later tests never started. Three
Cron identities are corrected. Socket recovery now pins the old inode through
probe/recheck using a temporary identity-checked hard link; a macOS test is added.
P2-26a is ACCEPTED from native W458 and actual Main/Buddy W480 consumer terminals,
with source carry verified. P2-26b macOS package/runtime stays independently open.
Core35959093253 is SUCCESS and its CLI export remains byte-identical8d97c9a7.
Inventory:1312portable native + Windows33/Linux47/macOS47; Group1042;
Windows focus50; GUI149Linux145macOS. New source behavior awaits GitHub checks.
Road:1324total/1046checked/276open/2partial;278raw/277pre-tag blockers.
WS-LF top-level remains38done/80open. No local executable validation.
See docs/gold-wave673-slack-and-hosted-repairs.md and W668-W672 receipts.

**W658/W661-W663 GUI acceptance and hosted build repairs (2026-09-24):**
GUI149run35956046048 atb71ebba3 is Root-admitted149PASS0FAIL0missing.
Three ZIPs,29source/inputbindings and149execution receipts plus logs verified.
W480 real producer Main/Buddy capture and mixed-incognito Recents both pass.
23GUI files carry byte-identically; main.rs carries only reviewed hosted formatting.
macOS ARM64run35956343411 atce42784e fails daemon compilation with E0277/E0308
from overloaded String+&String pairing-secret construction; explicit format!
concatenation retains both UUIDs. No GUI/bundle/runtime acceptance from that job.
W662 imports the exact hosted four-file rustfmt patch for009cabbf, verifying
ZIP,receipt and all old/new Gitblobs. Group1025run35959095156 stopped before
compilation at one stale990shell count; both catalog checks now require1025.
New native/Windows/package results remain pending; no local executable validation.
No Road closure. See W658/W661/W662 verification receipts.

**W654/W655/W657/W659 account routing and Windows stage repair (2026-09-24):**
Routing saves schema2 with explicit legacy-unbound or exact ChannelRef targets;
load remains read-only, duplicate/mixed inputs reject, retired legacy Keet input
is discarded. Cron seals authenticated Telegram accounts before admission;
unbound queue items cannot acquire accounts through later route edits.
35 focused native identities cover parsing, compatibility, actual caller rejection,
queue preservation/recovery and stage replacement. Portable native1295;
Group1025, Windows48. Independent static review; new hosted behavior pending.
Windows47run35956846675 atafbb5ebb is Root-admitted43PASS4FAIL0missing with
55hashes10sources2inputs. Released-DELETE twin47PASS identifies the retained
DELETE-parent sharing boundary. Paperless now keeps a read capability through
nested writes and late identity-checked mutation rebind. Diagnostic46 explicitly
becomes a sharing-error/no-publish/cleanup contract; production acceptance stays open.
Core35956844607 passes slimClippy, testtypecheck and CLIbuild/export; verified
CLI reference8d97c9a7 is imported before the next grouped run.
See docs/gold-wave659-routing-paperless.md and W657 verification receipts.
No Road closure; no local executable validation.

**W651/W653 admitted delivery component and reproducible Obsidian0.2 (2026-09-24):**
Plugin replay35956842325 atafbb5ebb passes all7 stages and12/12 bundle tests.
Root verified three ZIPs, exact source bindings and byte equality of all three
committed bundle files. Native daemon/installer and real Obsidian acceptance
remain separate pending evidence.
All12 W535 connection-bound delivery tests are source-admitted from Group977;
the three criterion-bearing current Git blobs match the admitted source.
The component now records behavioral acceptance rather than stale hosted-pending.
GChatW567 remains its separate4/4feature evidence. Full P1-14 channel coverage
remains open; no new whole-job or live-provider gate is introduced.
No Road closure or local executable validation.

**W648-W650 Obsidian0.2 generated bundle and cross-platform build repair (2026-09-24):**
Hosted plugin35956341651 atce42784e passes typecheck/build and all12 actual
bundle tests, including129-note finite batches, newer-ACK protection, re-pair,
offline retry, stalled-pipe timeout and unload. Root verified all three ZIPs,
six exact source Gitblobs and three bundle hashes; unchanged manifest/lock match.
The generated main.js (SHA256B1DC532BC781057BA6D3A95EB2A29D559C53FFA9AED5CBEB87B0679899C9CAD2)
is imported byte-exact. The job's expected old-bundle drift is still a failure;
a fresh committed-bundle replay remains required.
Core35956044188 exposed9Clippy errors; narrow borrow/CFG/tail repairs remove
them without changing authority. Windows4735956048283 compiled0tests: the new
owner used std metadata dev/ino unavailable onWindows. It now uses the existing
no-follow directory capability and its cross-platform physical metadata.
W477 independently approved; Windows handle diagnosis and native behavior
remain pending. No Road closure or local executable validation.

**W645-W647 finite Obsidian batching and hosted macOS continuation (2026-09-24):**
Plugin run35956042379 atb71ebba3 passes immutable install, TypeScript and build;
11/12 actual bundle tests pass. The129-note test exposes overlapping per-note
sync during initial scan (largest persisted queue2instead128). The reviewed
repair retains the finite scan until the batch is persisted, then starts one
sync; existing assertions stay unchanged. Its generated candidate is not imported
while this behavior fails. Source6 and all three bundle hashes were verified.
The exact two-file hosted formatter patch10790502239 was verified and imported.
The macOS hosted lane now allows180min and separates unchanged actual release
daemon/GUI builds, retaining timestamps and compiler logs per phase. Bundle
assembly and real Main/Buddy probes remain mandatory; local BSOD hold remains.
New hosted behavior is pending. No Road closure.

**W639-W644 hosted failure admission and focused repairs (2026-09-24):**
Root independently admitted GUI148 run35952003959 at701d5ebf:147PASS/1FAIL,
29 source/input bindings and every ordered terminal/execution receipt. W480
passed the typed captured Block/Replace checks but timed out on missing Buddy
recents. The production BridgeSink now syncs canonical recents after current
operation/turn/surface projection. Review found retained private rows could
leak on a later normal turn; the common helper now filters each incognito row,
with a new mixed-session regression. W480 itself remains unchanged.
Windows46 run35953571699 at83dd6ae1 is independently admitted42PASS/4FAIL:
54 internal hashes,10 sources,2 build inputs and46 terminals. W635 did not
repair the sharing violation. A test-only twin drops just the retained DELETE
binding before nested create-new, preserving the original failure witness.
Obsidian0.2 actual hosted compile errors are corrected: TFile event guard,
immutable pairing capture, unused Rust import and explicit anyhow conversion.
The exact12-file hosted rustfmt patch at2a09cc5d is digest/blob verified and
imported. New behavior remains hosted-pending; main.js is still the prior
artifact until the real0.2 build is imported. GUI116 universal/149Linux/145macOS;
Windows-only native31, focused Windows47; Group990 unchanged. The macOS package
run35947230118 timed out during both actual builds; no packaged runtime passed.
No Road closure or local executable validation.

**W638 Obsidian0.2 pairing and exact-revision source batch (2026-09-24):**
Pair/unpair/pairing-status now use authenticated resident Connector-Control;
the plugin receives only its scoped pairing payload. Pair and sync retain the
actual CC operation lease. Unpair durably revokes before listener withdrawal
and drain, and remains available after policy pause. Unix crash recovery checks
the daemon PID lock, owned socket identity and bounded refusal probe.
The capability planner binds the paired physical vault and selects the exact
plugin HMAC descriptor from NFC paths/raw note bytes. Sanitized selected ingest
and its source/revision ledger share one SQLite transaction, preventing replay
from becoming extra corroboration. The plugin preserves bounded opaque queues,
newer revisions, re-pair/unload epochs, settings and explicit offline retry.
Authentic0.1.0/0.1.1 predecessors remain supported; two real0.1.1 update/recovery
tests preserve notes/settings.13 new native cases bring universal1260,
Linux47/macOS46 extras and Group990. Independent reviews and Root corrections
are recorded; plugin bundle generation, native compile and behavior remain
pending. The artifact job records candidate tests even on expected bundle drift
while retaining the drift failure. No Road closure or local executable run.

**W636 complete grouped recall regression pass (2026-09-24):**
Group977 run35952811727 at258c0653 is independently admitted977PASS/0FAIL/
0missing with191 source/input bindings. All six new operator-anchor and actual
four-grader-input tests pass, including explicit selection, no overwrite,
complete response matrix, observed empty answers and marker-last publication.
Root verified all three artifact ZIPs and reran the source/terminal verifier.
This accepts those regression results; actual provider grading and the wider
P1-08 acceptance remain open. No Road closure or local executable validation.

**W634/W635 Windows rename-root access correction (2026-09-24):**
Windows46 run35952002227 at701d5ebf is independently admitted42PASS/4FAIL/
0missing:54 internal hashes,10 fixture sources,2 build inputs and46 actual
terminals. All four Obsidian update cases pass. Paperless38-40 and the isolated
retained-DELETE-parent regression46 still fail at rename with sharing violation
0xc0000043/0x20; W628 is therefore not a successful fix. W635 opens a separate
capability-relative rename root with FILE_TRAVERSE|FILE_READ_ATTRIBUTES and
passes it to private create-new rename. Private replacement and other paths
retain their behavior. Independent static review passes; the same46 hosted
regressions must establish runtime behavior. No Road closure or local execution.

**W631 exact CLI reference admitted (2026-09-24):**
Core run35951389963 at1a92014b passes slim Clippy, core test-target checking,
CLI build and export. ZIP digest, exact source receipt and generated reference
SHA256 are verified; the byte-exact reference now documents `anchor-link-create`
with `--link-output` and `responses-prepare`. Later CLI changes are solely the
admitted hosted formatting88dccde6. Group977 now has the updated snapshot for
its behavioral run. Preflight7d2f77e1 passes. W622 resident pairing/sync and W630
0.1.1 predecessor support remain uncommitted work; no Road closure or local
executable validation is claimed.

**W624/W626/W628 focused Windows repair and capture diagnostics (2026-09-24):**
Windows41 run35950133017 at235fa68e is independently admitted38PASS/3FAIL/
0missing with49 internal hashes and11 source bindings. All three failures now
pin the operation to `atomic_stage=rename;atomic_raw=Some(32)`. W628 routes only
private create-new stages through the existing capability-relative no-replace
information class; private replacement keeps FileRenameInformationEx. Native
collision codes retain AlreadyExists. A Windows fixture reproduces the retained
DELETE-parent composition; Windows-only inventory30 and hosted lane46 now include
it and the four Obsidian update cases. Runtime verification is pending.
W624 keeps W480 strict and checks Block/Replace typed capture terminals directly
before replay, before/after the second capture. Its content-free event snapshot
is captured before attach consumes the queue. Three unused packaged-probe
imports are removed. Independent static review approves both scopes; no Slint,
visual-token or UI copy change is involved. GUI behavior and packaged acceptance
remain separate pending gates. No Road closure or local executable validation.
**W618/W620/W623 actual grader inputs and admitted regressions (2026-09-24):**
Group971 run35949861050 ate1faeccf is independently admitted971PASS/0FAIL/
0missing with188 source bindings; all four pinned Obsidian update/recovery
cases pass. The Windows lane now adds those same four cases (45 selected) to
exercise their actual Windows filesystem composition after the current41 run.
GUI148 run35947837413 atd6d76425 is independently admitted147PASS/1FAIL,
148 exact terminals and29 distinct source/input bindings. W480 now diagnoses
settled Main rows incorrectly marked complete for a blocked capture; its strict
acceptance remains open while the projection path is traced.
W618 adds offline `responses-prepare`: actual complete100-query/two-system
answers and explicit rubric produce four canonical grader inputs and the
existing digest marker. It binds the exact goldset bytes, preserves observed
empty answers, refuses duplicate/missing/unknown pairs and publishes the marker
last without overwriting. Four new behavioral regressions are independently
reviewed; hosted validation is pending. W621 fixes `--link-output` so global
`--output json` retains its original meaning. Catalog1252 native/Group977.
W614 core235 passes Clippy/test-target check/CLI build; its old generated CLI
surface is superseded by this correction and the next exact export. W619
hosted formatting44cb passes Preflight. No Road closure or local execution.
**W614/W617 operator-anchor creation and Windows atomic diagnosis (2026-09-24):**
The new `recall-parity-harness anchor-link-create` consumes explicit operator
labels and exactly20 sorted query/candidate selections after signature/current
custody validation. It revalidates the canonical link and creates a new output
file in a bound existing parent without overwriting. Two universal regressions
cover canonical construction, duplicate/unknown-field rejection and no-overwrite.
The public runbook and methodology now document this missing operator step.
Independent review approves the source and corrected test ownership; hosted
formatting, compilation and behavior are pending. Catalog:1248 universal native
and Group973. W617 exposes only test-side atomic operation/ErrorKind/OS-code
for the three Windows Paperless failures; production sharing, fences and error
propagation remain unchanged. Group971 is running at the preceding published
source. No Road closure, live grading or local executable validation.
**W615-W616 Windows diagnosis and hosted CLI export (2026-09-24):**
Core run35948530640 at33e8a9a3 passes slim production Clippy, core test-target
checking and public CLI build/export. The generated reference is imported
byte-exact after ZIP digest, source receipt and SHA256 verification; it adds
`obsidian bridge update`. Group971 can now exercise the four native update
cases. Windows41 run35948232925 ataeab1fe0 is independently admitted38PASS/
3FAIL/0missing with49 internal hashes and11 source bindings. The three guarded
installer failures share `stage=write_owned_file;kind=Uncategorized;raw=Some(32)`.
Test-only inner-operation diagnosis is next; no speculative sharing or identity
fence change is accepted. GUI W480 and macOS package execution remain pending.
No Road closure or local executable validation.
**W611-W612 full grouped pass and locked plugin replay (2026-09-24):**
Group967 run35947835430 atd6d76425 is independently admitted967PASS/0FAIL/
0missing with188 source bindings; both supplied-keychain cases pass. Obsidian
0.1.1 replay35948528551 at33e8a9a3 passes all seven stages and3/3 Node contract
tests with six source bindings and exact equality of all three committed bundle
files. Four new native update regressions await Group971 after the new CLI
reference export. Windows preparation, GUI W480 and both macOS package runs
retain their separate pending acceptance. No Road closure or local execution.
**W608-W609 generated Obsidian0.1.1 artifact imported (2026-09-24):**
Hosted run35948230490 ataeab1fe0 passes immutable npm install, typecheck and
bundle build. Three ZIPs, six source Gitblobs, three bundle hashes and unchanged
manifest/lock were independently verified. The generated main.js SHA2560d7e20c5
is now imported exactly; the only emitted-code change is version0.1.0 to0.1.1.
The first run stopped at expected tracked-bundle drift, so its tests were not
run. A locked replay and fresh CLI export/native checks are next. W609 imports
the exact two-file hosted rustfmt patch. No Road closure or local execution.
**W600 Obsidian update and W604 Windows diagnostics (2026-09-24):**
The offline `obsidian bridge update` now accepts the exact retained0.1.0
predecessor and transitions its known payload to0.1.1. Vault notes, data.json
and unknown additions survive. Four new regressions cover exact/idempotent
update, tampered predecessor refusal, panic before marker publication with
predecessor recovery, and competing payload replacement. Review passed; the
0.1.1 generated main.js, CLI reference and hosted native checks remain pending.
Current main.js is deliberately the old generated artifact until the hosted
export is imported; no release or pairing/sync completion is claimed.
W604 Windows41 atc9d070e9 is admitted38PASS/3FAIL/0missing,49 hashes and11
source/input bindings. HTTP bootstrap passes; all three remaining failures
are preparation Io without a concrete syscall. Test-only stage/ErrorKind/OS-
code diagnostics now expose that failure without paths or secrets, preserving
product behavior and all fences. W606 imports the exact one-file hosted
config formatting patch. Catalog:1246 universal native, Group971; GUI148 and
Road1045checked/277open/2partial unchanged. No local executable validation.
**W599 supplied-store repair and W601/W603 GUI diagnosis (2026-09-24):**
Paperless final token persistence now loads effective credentials under the
canonical config authority using its already-open supplied keychain store.
This removes the accidental ambient Linux keychain read before the injected
store could participate. The existing authority wrapper and lock order stay
compatible; a new regression checks read failure cannot write the token.
Independent review approves; universal native catalog1242 and Group967 include
this case, with hosted execution pending. GUI148 run35943595820 at1a304f03 is
source-admitted147PASS/1FAIL/0missing with28 bindings and148 exact receipts.
W480 alone times out during GUI settlement after successful producer capture.
W603 adds only content-free in-flight/role/phase timeout diagnostics; timeout
and acceptance assertions remain unchanged. P2-26a remains open. Windows41
c9d070e9 has completed with failure and its exact results are being admitted.
No local executable validation or Road checkbox change.
**W599/W602 grouped evidence and macOS release toolchain (2026-09-24):**
Group966 run35945986803 atce8caa19 is independently source-admitted with
965PASS/1FAIL/0missing and188 bindings. The lone failure is the Paperless
supplied-keychain fixture entering the ambient OS keychain through config
loading; a narrow repair is under way. Package run35946989585 reaches the
actual release-desktop dependency set, whose locked Matrix SDK0.18 requires
Rust1.93. The new package lane now matches the existing release/preview pin
1.93.0 and isolates its cache accordingly; no feature or dependency is removed.
W593 Preflight35946989744 at9e14e5fc passes after exact hosted formatting.
Package runtime, GUI148 terminal admission, Windows41 and Road closure remain
pending; no local executable validation ran.
**W597 hosted package-probe formatting (2026-09-24):**
Preflight35946845117 generated an exact three-file rustfmt patch for W593
sourceda5635c6. ZIP digest, receipt hashes and every old/new Gitblob were checked
before import. No local formatter ran. Both macOS package targets are next;
P2-26b remains open pending their real runtime receipts. Group966 atce8caa19
has finished with a failure; its individual terminals are being admitted before
diagnosis. Windows41 and GUI148 remain independently in progress.
**W593 packaged macOS chat acceptance implementation (2026-09-24):**
The opt-in packaged-chat acceptance mode now drives the production Main/Buddy
callbacks against the sibling packaged daemon in a fresh temporary NEOTH_HOME.
It checks streamed Buddy-to-Main handoff of the same turn/cursor, exactly one
visible completion, request-bound provider failure and cancellation, then an
exit-zero daemon drain and temporary-home removal. A separate process driver
checks all required receipt facts and absence of surviving package processes.
The manual macOS ARM64/x86_64 lane builds release-desktop binaries into an
ad-hoc signed app bundle. This is not Developer-ID, PKG/DMG, or clean-machine
release qualification. Static review passes; hosted formatting/build/runtime
checks remain pending, so P2-26b remains open. Slint and visual tokens are
unchanged; no new controls, styling, motion or UI copy require a design-lint
claim. Runtime behavior awaits the package lane; visual/accessibility release
criteria remain separate. Windows41 evidence W595 is independently admitted
37PASS/4FAIL with49 hashes and11 source/input bindings; the reviewed repairs
are published c9d070e9 and hosted recheck35946534967 is running. No local tests.
**W595 Windows Paperless regression repairs (2026-09-24):**
The hosted Windows41 run35944218754 atf1ca9b67 compiled and selected all41
identities, with37PASS/4FAIL/0missing. Three guarded installer cases failed
before dispatch while preparing the stage: a read handle preceded the Windows
mutation binding. Preparation now binds first and uses the existing identity-
checked, delete-sharing reader. The HTTP token fixture now fully consumes its
bounded form body before replying, avoiding a premature socket close. Production
token transport and the launch fences remain unchanged. Both fixes passed
independent static review; fresh hosted Windows41 execution is required.
Group966 atce8caa19 and GUI148 at1a304f03 are still running. The matching
ce8caa19 Preflight passes. No Road closure or local executable validation.
**W594 Paperless core and CLI reference accepted (2026-09-24):**
Run35944853152 ata881e642 passes slim production Clippy, core test-target
checking, public CLI build and reference export. Artifact10786119710 binds
sourcea881e642 and reference SHA2565e7c52fe; its only reference addition is the
new `neoth paperless install` command. The generated bytes are now imported.
Group966 can run against this matching snapshot. Windows41 and GUI148 retain
their independent source-bound acceptance; no full cross-platform or actual
Docker installation claim. P2-20/002-09 and P2-26a remain open. No local
executable validation or Road checkbox change.
**W585/W590 evidence and W592 Clippy follow-up (2026-09-24):**
Group951 run35943593327 at1a304f03 is source-admitted951PASS/0FAIL/0missing
with186 Gitblob bindings; the actual W458 Block/Replace producer terminal passes.
The earlier GUI148 run35941273881 at0e97dcca is independently admitted
145PASS/3FAIL with28 bindings: two Wizard text contracts and W480 ending before
Terminal. W581/W583 postdate that run; GUI148 at1a304f03 remains the fresh check.
P2-26a stays open until its own Main/Buddy consumer terminal also passes.
W589 imported seven exact hosted formatting transformations; Preflight
35944393728 at83c3e29d passes. Core35944216594 at the pre-format f1ca source
reported three formatting lints and two narrow Clippy lints. W592 removes a
redundant parser closure and splits the unit/non-unit launch guard by platform,
preserving the Windows guard lifetime. Hosted recheck/CLI export remain pending;
Windows41 continues independently. No local executable validation; no Road
checkbox changes. Paperless installation on real Docker is not yet accepted.
**W574 Windows-managed Paperless install (2026-09-24):**
The async `paperless install` command now pulls the three admitted OCI pins,
selects a fixed local Linux-engine endpoint/platform, verifies image config IDs,
and starts the retained Compose contract with `--no-build --pull never`.
Windows holds every launch ancestor, state/mount directory and read-only
Compose/env handle until container and authenticated API checks complete.
Ambient interpolation overrides are removed. Missing tokens bootstrap only
after all three container bindings, then persist through the selected file or
Keychain backend; existing tokens remain untouched. Private receipts publish
only after post-readiness container revalidation. Other OS launch is explicitly
unavailable; actual Docker installation, update/rollback/uninstall and P2-20 /
002-09 acceptance remain open. Hosted formatting, CLI export and behavior checks
are pending; no local executable validation ran. Catalog: 1241 universal native
plus Windows29/Linux42/macOS41; Group966; Windows41 focused selection. GUI and
Road counts are unchanged (1045 checked /277 open /2 partial).
**W583-W584 stream follow-up and core (2026-09-24):**
Core35941268561 at0e97dcca passed slim Clippy, test-target typecheck, public CLI
build and reference export; the reference remains byte-identical (0bd07415).
Group95135941271455 admits950PASS/1FAIL/0missing and186bindings. W458 now fails
inside its eight-frame capture bound afterW577 added one accepted GUI Delta.
W583 preserves Block's maximum8 and permits exactly one additional frame for
Replace (maximum9); every strict no-secret/body/count/order/digest assertion
remains. Bounded diagnostics name only frame kinds. Independent review passed;
fresh native/GUI execution is pending. P2-26a and all Road counts stay open.
W582 imported only GitHub formatting for the W581 test helper; Preflight
35942356921 at0462679b passes. No local executable validation.
**W579-W581 GUI follow-up (2026-09-24):**
GUI148 run35938022418 atc21e29b1 is admitted145PASS/3FAIL/0missing with28source
bindings. W480 Replace lacks the accepted Delta addressed byW577. The other
two failures are whitespace-sensitive Dream/Wizard source-contract assertions;
W581 normalizes whitespace/trailing field commas only in those tests, keeping
all lock, retained-readback, ordering and fail-closed checks. Production code
is unchanged. Both P118 GUI callback cases pass again. Independent review and
scoped diff checks pass; new GUI execution remains pending.
W580 imports exact GitHub formatting for W577 (old/new Gitblob + ZIP/receipt
checks), and Preflight35941526082 passes ata1e01e71. No local formatter/tests.
Road1045checked/277open/2partial and test-selection counts remain unchanged.
**W577 accepted stream projection (2026-09-24):**
The sole Group951 failure is repaired in source: accepted deferred provider
output now carries a typed body to the GUI sink while the CLI writes its
unchanged authenticated frames exactly once. W458 additionally checks strict
Delta < ProviderDone < Terminal order, retaining no-secret, exact body/digest
and Main/Buddy parity assertions. Independent static review approved; fresh
native W458 and GUI W480 terminals are pending. No P2-26a closure yet.
W576 also admits all seven repaired SQL regressions in Group951; historical
Windows browser/WAL failures are covered by the admitted Windows24 run.
No local executable checks. Road and test-selection counts are unchanged.
**W576 native lifecycle evidence (2026-09-24):**
Group95135939403055 atc38fae1c admitted950PASS/1FAIL/0missing,186bindings and
all951actual terminals. All15Obsidian lifecycle/CLI/race cases and both W570
Paperless contract cases pass; parity-inventory and2default-account regressions
also pass. W458 alone fails: Replace yields0accepted deltas instead of1 after
the replay-cursor repair. Strict assertions stay; W577 investigates this cause.
No new Road closure; P2-21pairing/update and P2-26a remain open. Evidence:
docs/verification/gold-wave576-native-selected-terminals.json.

**W575 recursive Paperless bytes admitted (2026-09-24):**
Hosted35939610119 at69a59828 passed13contracts and verified75distinct config/
layer blobs (76references,1duplicate),1,951,126,239bytes over162requests. Root
verified ZIP+receipt+4Git sources+9raw manifests+all recursive descriptors and
exact current staging pins. Permanent receipt/BLOB_ADMISSION sit beside the
unchanged9manifests in docs/verification/paperless-oci-v3.2.1/. No local images,
containers or executable checks ran. Installation/readiness and P2-20 remain
open; W574 now implements the consuming native install path. Counts unchanged.

**W573 observed Docker CDN (2026-09-24):**
Paperless35939400996 atc38fae1c passed13contracts, then rejected the actual
Docker CDN production.cloudfront.docker.com. That exact hostname is added only
to Docker's redirect set; a regression rejects it for GHCR. Digest/size checks,
limits and credential stripping remain unchanged. Fresh acquisition pending.
Preflight35939387138 passed, including the repaired Road/LF count contracts.

**W568/W570 integration and W572 core/reference (2026-09-24):**
The recursive OCI checker now hashes actual configs/layers with bounded
streaming, explicit CDN hosts, stripped redirect credentials and exact size/
digest checks. Full selector-to-blob and negative fixtures protect the real
handoff. Initial hosted35938744354 passed contracts then rejected an unknown
CDN; no blob acquisition is admitted yet. The staged Paperless contract exposes
its metadata-only coverage and preserves state when refusing a stale marker.
Two new Rust cases raise native1228/Group951; all changed source bindings are
reconciled after early parallel publication. P2-20 remains open.
Core35938019476 atc21e29b1 passed slimClippy, test-target typecheck, CLIbuild and
reference export; its SHA-bound Obsidian bridge reference is imported. W570
postdates that source; its behavior remains pending in Group951. W571 closure
counts are now synchronized in the release-gate marker and both LF dashboards:
1045checked/277open/2partial; WS-LF38done/80open. No local executable checks.

**W571 P1-18 accepted; W569 hosted formatting (2026-09-24):**
GUI148 run35935063658 at829c37c3 is admitted147PASS/1FAIL/0missing,28bindings.
Both real P118 GUI callback cases pass; all13native WizardIPC support cases
already pass in Group934. Exact scoped source carry (only admitted W560format
for main.rs) closes GOLD-LF-P1-18 independently of the sole W480 failure.
Road now1045checked/277open/2partial,279raw/278pre-tag; WS-LF38done/80open.
W569 imports only2Obsidian Rust format files from preflight35938006795 atc21e29b1,
with ZIP/SHA256/before-after Gitblob verification. No local formatter executed.
Evidence:docs/verification/gold-wave571-p118-acceptance.json.

**W567 GChat hosted confirmation (2026-09-24):**
Run35936050813 at3bd923a0 is admitted4/4PASS with3ZIPdigests,8sourcebindings,
discovery hashes and all actual terminals verified by Root. This confirms the
same-live-instance delivery fix for both aliases and preserves missing/revoked
no-send behavior. No external Google Chat service qualification is claimed.
Evidence:docs/verification/gold-wave567-gchat-terminals.json.

**W559/W565/W566 Obsidian lifecycle and hosted follow-up (2026-09-24):**
The actual pinned Obsidian bundle now has native status/install/repair/uninstall
commands with exclusive capability-bound publication, settings/extension
preservation and resumable uninstall. Fifteen new module/CLI/race cases join
Group949; native1226 plus Windows25/Linux40/macOS39. Independent review passed;
new hosted compile/behavior is pending. Pairing/sync and P2-21 remain open.
Group934 at5a5b13ea is admitted:930PASS/4FAIL/0missing,184bindings; all29Paperless
and13WizardIPC cases pass. The four failures have scoped fixes: publishedW561
account binding, corrected production Finish inventory anchor, and W566's
authenticated replay cursor. Strict provider/secret/terminal checks remain.
Road1044checked/278open/2partial and WS-LF37done/81open unchanged.
Details:docs/gold-wave559-566-obsidian-lifecycle.md.

**W561 live delivery default-account repair (2026-09-24):**
GChat35934263615 executed all4feature cases; the positive same-instance case
failed because the queued item retained account_id=None while its v6 permit
correctly named the concrete default account. The dispatcher now seals that
planned ConnectionBound account before entering Egress. The prior explicit-
account path still exits before this step, preserving mapped account authority.
Independent review approved. Missing/revoked routes remain no-send; corrected
feature execution is pending. Road and test-selection counts remain unchanged.

**W558 artifact admission; W562 current CLI reference (2026-09-24):**
Hosted35935325488 at77d914b7 passed TypeScript, bundle build and3/3plugin
contract tests. Root admitted6source hashes,3artifact ZIP digests, all exit
receipts and the exact manifest/lock/bundle; generated files are now imported.
This proves package behavior against a fake API, not live Obsidian pairing/sync.
Core35934260205 atce7394ba passed slimClippy, test-target typechecking and CLI
build; its source/SHA256-bound paperless prepare reference is imported. Group934
can now run without the known stale CLI snapshot. New lifecycle code remains
separately reviewed/pending; Road and native/GUI counts remain unchanged.

**W558 pinned Obsidian artifact source; W560 hosted format (2026-09-24):**
The Archive Bridge now has a real TypeScript Obsidian Plugin entry, manifest,
pinned SDK/compiler/bundler and a main-only hosted artifact lane. Version0.1.0
is a read-only inspector for NEOTH-sessions; pairing/sync remain visibly disabled.
GitHub will typecheck/build/test and retain source hashes, generated lock/bundle
and per-stage logs/exit receipts. Native installation is not published until the
actual bundle is admitted. Independent source review complete; execution pending.
W560 imports the exact GUI format patch from35935063648/artifact10782528643
with source/SHA256/before-after blob verification. Native1215/Group934+GChat4,
GUI148Linux144macOS and all Road counts unchanged; P2-21 stays open.
Details:docs/gold-wave558-560-obsidian-artifact.md.

**W554/W557 real Wizard callback and GUI evidence (2026-09-24):**
GUI1486146 run35929972686 is source-admitted:148executed/145PASS/3FAIL/0missing,
with28input/source bindings and148actual test terminals. Cancellation reached
its terminal state but its fixture never registered the production Finish
callback. Daemon-loss incorrectly required stale descriptor files to vanish.
Production and tests now share the real frozen Finish registration; the two
cases require zero normal completion calls, no replacement operation and the
exact reconciliation status, plus actual same-boot connection failure after
process loss. Independent review approved; corrected execution remains pending.
W480 failed before provider start and is covered by the pending W550 rerun.
No Road closure:1044checked/278open/2partial; WS-LF37/81 unchanged.
Details:docs/gold-wave554-557-wizard-evidence.md.

**W555/W556 hosted compile and format follow-up (2026-09-24):**
GChat35933359541 stopped before discovery at a Paperless test E0382; W555
clones the moved fixture path while preserving the final directory assertion.
W556 imports6exact hosted format files from35933358886 after ZIP, SHA256 and
before/after Gitblob checks. GUI1486146 reports145PASS/3FAIL; W480 is covered
by the pending W550 rerun, while two P118 failures remain under diagnosis.
No new Road closure; native1215/Group934+GChat4 and GUI148Linux144macOS
unchanged. No local executable validation. Details:docs/gold-wave555-556-compile-followup.md.

**W552 GChat workflow dispatch correction (2026-09-24):**
W547-W551 is published asa7019b9e; core35933302798 dispatched. GitHub rejected
the GChat lane before execution because runner.temp is unavailable in job-level
env. Its evidence root is now initialized from RUNNER_TEMP in a runtime step.
No GChat fixture or acceptance is claimed from the rejected dispatch.

**W547-W551 publication and live-chat follow-up (2026-09-24):**
Group903a53 run35930437377 is admitted902PASS/1FAIL/0missing with179bindings;
all13Paperless readiness and13Wizard IPC support cases passed. W550 repairs
the sole W458 test-adapter capability omission while keeping strict stream checks.
W547 capability-binds Paperless creation/inspection and exclusive source-bound
publication; four race regressions join the lane. W548 routes both Google Chat
aliases through the running instance and revokes on receive-task exit; four
feature-specific cases have a separate hosted lane. W551 adapts existing test
callers to opaque one-shot permits after7actual hosted test-compile errors.
Independent static reviews complete; executable verification of these changes
is pending. Inventory776/native1215+Win25Linux36mac35, Group934+GChat4;
GUI148Linux144macOS unchanged. Road1044checked/278open/2partial, WS-LF37/81
unchanged. Evidence:docs/gold-wave547-551-followup.md.

**W545/W546 hosted gate follow-up (2026-09-24):**
Core535 run35930665250 reached the new constructor and failed one Clippy
too-many-arguments lint; its explicit authority inputs now use the established
scoped documented exemption. Four exact Paperless hosted format files from
35931033658/artifact10780488191 were source/SHA256/Gitblob-verified and imported.
W547 additionally repairs an identified no-overwrite publication race; that
follow-up is not yet accepted. No new behavior or Road closure is claimed.
Inventory773/native1213/Group929; Road1044checked/278open/2partial unchanged.

**W540 native Paperless preparation; W544 hosted format (2026-09-24):**
Paperless prepare stages deterministic OCI-pinned Compose and a secret-free
example, preserves operator env/state, refuses foreign or symlink paths, and
reports preparation separately from authenticated API readiness. No Docker,
image verification or lifecycle completion is claimed; P2-20 remains open.
Seven new portable cases, one Unix case and six existing cases enter Group929.
Inventory773/native1213+Win25Linux34mac33; GUI148Linux144macOS unchanged.
W535's exact3-file hosted format patch was hash/blob-verified and imported
from35930665319. Independent review complete; new executable checks pending.
Road1044checked/278open/2partial remains unchanged. See docs/paperless-readiness.md.

**W535 connection-bound durable delivery (2026-09-24):**
Opaque one-shot live permits now bind v6 Claim/Intent/Armed/Result/history to
the exact ChannelRef, generation and fingerprint. Expired Armed recovery
records CrashUnknown without reacquiring or resending. Two new regressions and
ten existing live-route cases enter Group915; native1200, source771.
Independent static review complete; hosted format/build/behavior pending.
P1-14 remains open. Road1044checked/278open/2partial, GUI148Linux144macOS unchanged.
Evidence:docs/gold-wave535-connection-bound-egress.md.

**W543 hosted CLI reference (2026-09-24):**
Core35928759424 at96f86a92 passed core test-target typechecking and CLI build.
The source- and SHA256-bound export (artifact10780089697, reference62d831c4)
is imported for paperless status; this admits no native behavior or Road closure.
Inventory770/native1198/Group903 and Road1044checked/278open/2partial unchanged.

**W542 GUI bootstrap test import (2026-09-24):**
GUI148d2f4 run35927366772 compiled the production targets but its test harness
failed E0599 on the P118 bootstrap helper's Context trait. The helper now
imports anyhow::Context locally. No GUI fixture executed; P1-18/P2-26a stay
open. Core96f8 passed test-target typechecking and is building the CLI export.
Inventory770/native1198/Group903 and Road1044checked/278open/2partial unchanged.
**W539 Paperless metadata admission (2026-09-24):**
Hosted35928756605 at96f86a92 passed8/8contract tests and acquired9raw OCI
manifests. Root verified receipt/source hashes, all3indexes,6platform children
and every retained config/layer descriptor; permanent provenance is committed
under docs/verification/paperless-oci-v3.2.1. No layer/runtime or Ready claim.
Preflight35928755304 and CodeQL35928755635 passed. Inventory770sources;
native1198/Group903/GUI148Linux144macOS and Road1044checked/278open/2partial
remain unchanged. P2-20 stays open for consumed staging and lifecycle work.
**W537/W538 hosted correction (2026-09-24):**
Paperless acquisition's7contract tests passed; remote acquisition failed before
any admitted receipt. Verified upstream Docker metadata uses3.2.1 without the
GitHub tag'sv prefix; corrected selector and bounded HTTP-status diagnostics
are covered by an eighth test. Core d2f4 slim production Clippy passed; its test
typecheck exposed one stale Credentials path in the CLI fixture, now corrected.
Exact hosted GUI formatting was imported. Inventory759/native1198/Group903,
GUI148Linux144macOS and Road1044checked/278open/2partial are unchanged.
Execution follow-up pending; no local executable checks or closure claims.
**W531 Paperless OCI provenance; W534/W536 stream diagnostics (2026-09-24):**
A main-only hosted workflow acquires and retains three OCI indexes and six
exact platform manifests with bounded HTTPS and digest/size/media checks.
Seven direct/fake-client contract tests run hosted; no layer/image/runtime
verification is claimed and artifact_verified remains false. Root verified
the signed upstream release/commit and immutable compose hash. W534 imports
the exact two-file hosted formatting patch; W536 forwards fixed-label producer
diagnostics to the existing strict GUI assertion. Both source batches are
independently reviewed; execution is pending. Inventory759sources/1198native,
Group903/GUI148Linux144macOS; Road1044checked/278open/2partial,
280raw/279pre-tag; WS-LF37done/81open. No local executable checks or Slint edits.
Evidence:docs/gold-wave531-paperless-provenance.md.
**W525-W529 hosted Chat/Paperless follow-up (2026-09-24):**
Group8906b is admitted888PASS/2FAIL/0missing with176bindings. W526 aligns
accepted Replace termination/refusal expectations with production while keeping
the positive native-refusal path strict. W525 adds only allowlisted diagnostics
to the real GUI producer regression; its pre-provider cause remains unresolved.
Core8945 and GUI1488945 failed the same Credentials import; W527/W528 repair
its canonical module path. GUI ran0fixtures; no behavior is accepted from it.
Quality8945 passed both CodeQL jobs. W529 imports the four exact hosted format
patches after SHA256 and before/after Gitblob verification. W515's actual source
count was754, now corrected in its note. Inventory755sources/1198native,
Group903/GUI148Linux144macOS; Road1044checked/278open/2partial,
280raw/279pre-tag; WS-LF37done/81open. Fresh hosted execution and CLI export
remain pending. No local executable checks or Slint edits.
Evidence:docs/gold-wave525-529-hosted-followup.md.
**W515 Paperless readiness; W521/W523 hosted gate repairs (2026-09-24):**
`neoth paperless status` now reaches a bounded authenticated local API probe
through existing coherent file/keychain credentials. Unauthenticated profile
access must fail before Token auth; profile/status schemas, redirects, body cap
and a whole-sequence deadline are enforced. API-ready/version-unknown is distinct
from artifact verification, which stays false; P2-20 remains open. The TCP-only
scan cannot claim a running service. Eight HTTP cases, four CLI cases and the
port-only regression join the hosted catalog. W523 imports the six existing
production names needed by P118's nested GUI test module; GUI8003/Core8003 had
15scope errors and0GUIexecution. W521 synchronizes the human WS-LF dashboard
with37done/81open; the machine-readable Road summary was already corrected.
Inventory754sources,1198native+Win25Linux33mac32,Group903;
GUI148Linux144macOS,macNative33. Road1044checked/278open/2partial,
280raw/279pre-tag;WS-LF37done/81open. Reviewed source; fresh hosted checks and
CLI-reference export pending. No local executables or Slint edits.
Evidence and operator usage:docs/paperless-readiness.md.
**W518 reflection acceptance; W516/W519/W520 follow-up (2026-09-23):**
P2-04 is accepted:55exact Linux and55macOS terminals plus7fresh Windows
retention/quarantine/recovery cases; all24Windows cases passed at8003.
Root verified32artifact hashes,4input hashes,24ordered source/terminal bindings
and the10-path scoped carry. Group8908003 is admitted888PASS/2FAIL/0missing;
the scheduler now starts, exposing a terminal receipt-format mismatch. W519
uses canonical64hex lifecycle receipt IDs on all3terminal branches. W520
expects policy-redacted reasoning for the intentionally deferred Replace stream.
Both repairs are independently reviewed and await fresh hosted execution.
Preflightcd04 passed formatting but found the stale machine-readable Road
summary; W516 synchronizes that summary with the actual checkbox inventory.
Inventory748sources,1185native+Win25Linux33mac32,Group890;
GUI148Linux144macOS,macNative33. Road1044checked/278open/2partial,
280raw/279pre-tag;WS-LF37done/81open. Local BSOD hold remains absolute.
Evidence:docs/gold-wave518-reflection-and-stream-followup.md.
**W513 hosted formatting follow-up (2026-09-23):**
W502-W508 is published as8003a605. Preflight35922289920 failed only
Rust formatting; artifact10777886345 binds the single main.rs layout hunk
with both SHA256s and the complete before/after Gitblob pair verified.
The exact hosted patch is imported; no local formatter ran. Group890,
GUI148, Windows24 and Core continue at8003; the format-only carry does not
change their functional scope. Inventory746 and Road1043/279/2 unchanged.
**W502-W508 Q8 acceptance and hosted regression repair (2026-09-23):**
P1-09 is accepted from13 exact test/class terminals (6Windows+7macOS)
and10 scoped source paths, including the actual macOS-native W151 callback.
Group89042 is admitted888PASS/2FAIL/0missing with176source/input bindings;
both real-consent grammar regressions pass. W507 decodes the required
control-frame prefix without weakening the CLI stream assertions. W508 moves
admitted execution inputs into Turn: schedule_turn previously searched the
preflight map after start had removed the entry, so the provider never opened.
GUIc7 compiled unsuccessfully (11type errors,0executed); W504 fixes the two
causes. W503 imports source-bound hosted formatting only. P1-18 and P2-26a
remain open for fresh behavior results. Windows selection grows17to24 to
cover the seven concrete retention/quarantine/recovery gaps after the real
Windows store changes; P2-04 remains open until these pass.
Inventory746sources,1185native+Win25Linux33mac32,Group890;
GUI148Linux144macOS,macNative33. Road1043checked/279open/2partial,
281raw/280pre-tag;WS-LF36done/82open. No local executable checks ran.
Details:docs/gold-wave502-ouro-q8-acceptance.md and
 docs/gold-wave503-508-hosted-regression-repairs.md.
**W494/W499/W500 consent, streams and wizard; W495/W498 acceptance (2026-09-23):**
Group888c7 is admitted885PASS/3FAIL/0missing with176bindings. W500 repairs
an actual wire mismatch: real request-bound consent proofs use UUID.dot64hex,
while the prior GUI validator rejected the dot. Exact grammar regression
includes real ready/interactive mints. W499 decodes the actual CLI StreamFrames
carrier without weakening Block/Replace/secret/receipt assertions. The verified
hosted CLI reference adds only92new Buddy command lines. W494 adds2 real
serve-bootstrap GUI callback/loss cases and same-boot controller reconciliation;
P1-18 stays open pending execution. Windows17c7 is admitted17/17 with25artifact
hashes. P1-19 is accepted from33macOS+32Windows exact test/class terminals with
15-path scoped carry; P1-02 from14exact mirror cases. Inventory743sources,
1185native+Win24Linux33mac32,Group890,GUI148Linux144macOS,macNative33.
Road1042checked/280open/2partial;282raw/281pre-tag;WS-LF35done/83open.
No local executable checks. Details:docs/gold-wave494-500-consent-stream-wizard.md,
docs/gold-wave495-local-model-acceptance.md,docs/gold-wave498-mirror-refusal-acceptance.md.
**W496 hosted formatting import (2026-09-23):**
W488-W493/P219 is published asc7b946f1. Preflight35917397881 produced
artifact10776260380:2SHA256 entries and all3 complete before/after Gitblob
pairs verified before import. No local formatter ran. Group88835917416801,
GUI14635917420707,Windows1735917424314 and Core35917428582 validate c7;
CLIexport3de35916213648 remains separate. Road1040/282/2 and737-source
inventory unchanged. P118 now has a bounded served-GUI behavior follow-up.
**W491-W493 hosted failures and reviewed repairs (2026-09-23):**
Group88835914415313 is admitted884PASS/4FAIL/0missing with176bindings;
both new Buddy task-delegate tests pass. W488/W489 repair the two Chat
fixtures; W492 accounts for all9new Buddy leaves without overstating GUI
parity. Core9abb passed slimClippy/typecheck but failed23GUI workspace
Clippy diagnostics, now source-repaired. Windows16034 is admitted15PASS/
1FAIL: native parent rename returned Win325. Windows17 replaces the false
successful-swap claim with explicit refusal and independent decoy-path
publication tests. GUI146034 failed compilation at the cfg(test)-only
consent helper before0tests; the shared capture repair covers this boundary.
Hosted CLI-reference export35916213648 is queued. Independent source
reviews pass; fresh hosted results remain required for these repairs.
Inventory737/native1183+Win24Linux33mac32/Group888/GUI146Linux142macOS.
Road1040checked/282open/2partial;284raw/283pre-tag;WS-LF33done/85open.
Local BSOD hold remains. Evidence:docs/gold-wave491-493-hosted-repairs.md.
**W490 BudgetToken functional acceptance and W488/W489 Chat follow-up (2026-09-23):**
Group88635911456591 at9abb52d5 is source/terminal admitted:886executed,
884PASS,2FAIL,0missingterminals; all176source/input bindings verified. All38
BudgetToken identities pass, including real concurrent reservations from two
followers against one shared cap. P2-19 is accepted with partition, leader-change,
replay, recovery and paid-provider leaf evidence. The unrelated Chat failures
remain open: the CLI test incorrectly expected an exposed post-provider error,
and the real runtime attach reached EOF before its required terminal. W488
uses the intentionally opaque error plus exact HOOK_BLOCKED WAL causation;
W489 traces the missing runtime terminal without accepting EOF as success.
Preflight3de35914415349 and CodeQuality35914414156 passed. Group88835914415313
runs with the corrected action pin; GUI146 and Windows16 continue at03456722.
Inventory736/native1183/Group888/GUI146Linux142macOS;Road1040checked/282open/
2partial,284raw/283pre-tag;WS-LF33done/85open. No local executables ran.
Evidence: docs/gold-wave490-budget-quorum-acceptance.md.

**W487 hosted formatting and workflow pin repair (2026-09-23):**
W480/W484-W486 is published as03456722. Preflight35913977425 exported two
Rust formatting changes; artifact10773559802, both SHA256 entries and all
complete before/after Gitblob pairs matched before import. Group88835914021236
failed during runner action resolution before checkout or compilation: the
count edit had accidentally changed three upload-artifact pin strings. The exact
previous working pin is restored, and every workflow action reference was
compared with580c29e5. This run supplies no behavior result. Core03435914028695,
GUI14635914017454 and Windows1635914024705 continue; Group888 will be redispatched.
Inventory734/native1183/Group888/GUI146Linux142macOS; Road and WS-LF unchanged.
The local BSOD hold remains active; no local formatter or compiler ran.

**W480/W484-W486 producer consumers, Buddy parity and hosted efficiency (2026-09-23):**
Preflight 35911848078 passed at 580c29e5. Core9abb passed slim Clippy and
core test-target compilation; workspace Clippy and Group886 continue. Windows
35911460507 compiled/executed16:15PASS,1FAIL; the parent-swap hook now reports
Win32 5 instead of32. W486 uses the existing native relative POSIX rename in
that fixture while retaining both original publication assertions. W480 shares
real producer/attach frames with the actual desktop controller/sink/reducer and
requires visible Main/Buddy terminal/body/preview results. Initial replay cursors
and subscription identities are bound. W485 routes Buddy TaskDelegate through
the canonical cluster grammar/handler. W484 compiles the grouped test binary once
and preserves every exact fresh-process case, timeout and evidence marker; the
old run spent822.12s in repeated Cargo completion overhead. Source review and
hosted results are distinct; no new Road row closes in this publication.
Inventory734/native1183/Group888; GUI146Linux142macOS;macOSnative31.
Road1039checked/283open/2partial;WS-LF32done/86open. BSOD hold remains absolute.
Evidence: docs/gold-wave480-producer-consumers-and-batch-execution.md.

**W482 hosted formatting import (2026-09-23):**
W479 is published as 9abb52d5. Preflight 35911416396 exported formatting for
three Rust files; artifact 10772743046, both SHA256 entries and all complete
before/after Gitblob pairs were verified before import. No local formatter ran.
Core 35911452930, Group886 35911456591 and Windows16 35911460507 continue at
9abb52d5; formatting is the only source carry in this follow-up. W480 connects
the real producer capture to the desktop consumers. Counts remain
Inventory733/native1181/Group886; Road1039checked/283open/2partial;
WS-LF32done/86open. All executable gates remain on GitHub.

**W479 wizard acceptance and hosted repairs (2026-09-23):**
P1-22 is functionally accepted at d9382041: 18 required baseline identities
passed on both macOS and Windows, plus the real GUI prepare/commit/rerun test
passed in GUI145. All 145 GUI terminals and 24 source/input bindings are admitted.
Group885 completed with 882 PASS, two FAIL and one timeout; Windows16 completed
with 15 PASS and one retained-parent swap FAIL. Core8ec passed slim Clippy and
core test-target compilation; workspace Clippy found 11 diagnostics. W474-W478
repair those concrete failures and add the missing simultaneous two-follower
budget regression. The runtime lock repair requires no state guard over a WAL
await and preserves start/shutdown ordering. Fresh hosted results remain pending.
P2-19 and P2-26a remain open. Inventory733/native1181/Group886; GUI145Linux141macOS.
Road1324=1039checked/283open/2partial;285raw/284pre-tag;WS-LF32done/86open.
Evidence: docs/gold-wave479-wizard-acceptance-and-hosted-repairs.md. BSOD hold stays.

**W471 hosted formatting import (2026-09-23):**
W469 is published asf1c67422. Preflight35893107024 exported formatting for
six Rust files; artifact10766031308, both SHA256 entries and every complete
before/after Gitblob match before import. No local formatter ran. Core8ec
35892417444 continues. Group885/GUI145/Windows16 await core readiness.
Inventory731/native1180/Group885/GUI145Linux141macOS; Road and WS-LF counts
remain unchanged. All behavioral acceptance boundaries remain explicit.

**W469 live assignments and integrated regressions (2026-09-23):**
W467 is published as8ec8bf6a; Preflight35892387374 passed. Core35892417444
is checking its exact source. W465/W466 add daemon-owned authenticated scoped
and outbound CAS mutations, one-attempt live CLI routing and a shared outbound
authority gate. Existing offline mutations retain the exclusive daemon PID lock.
Both dispatch/deny orders have bounded regression coverage. W458 now runs the
real three-chunk producer through filesystem hooks into actual Main/Buddy daemon
attach streams; Block requires its exact WAL hook event and Replace its digest.
W468 executes real GUI preparation, private wizard commit and topology reload/
rerun. Independent static reviews passed; executable gates remain hosted/pending.
P1-22/P2-18/P2-26a stay open pending their actual remaining acceptance boundaries.
Inventory731/native1180+Windows23/Linux33/macOS32;Group885;GUI145Linux141macOS.
Road1038checked/284open/2partial and WS-LF31done/87open unchanged; BSOD hold stays.
Evidence: docs/gold-wave469-live-authority-stream-wizard.md.

**W467 actual hosted core diagnostics (2026-09-23):**
Preflight76e4 run35890366917 passed. Corea96 run35889966328 passed slim
production Clippy but failed the test-target check: two impl-level OpenRaft
macro panics, one anyhow/AnyError conversion error and three cascading factory
trait errors. The narrow repairs target these exact diagnostics; no hosted
behavioral pass is inferred. Group882, GUI144 and Windows16 await core readiness.
W465/W466 live assignments and the W458 real two-stream runtime regression are
under independent review. P1-22 remains open because existing passing wizard
terminals do not cover shared-executor persistence followed by topology reload;
W468 adds that missing regression. No Road checkbox changes in this checkpoint.
Inventory730/native1177/Group882/GUI144Linux140macOS; Road1038checked/284open/
2partial and WS-LF31done/87open remain unchanged. Absolute local BSOD hold stays.

**W463 hosted format import (2026-09-23):**
W462 is published as a96eeba5. Preflight35889935674 reported only formatting;
its five-file patch was imported after verifying both artifact hashes, source
HEAD and every full before/after Gitblob. No local formatter ran. Corea96
35889966328 continues; Group882, GUI144 and Windows16 wait for readiness.
Inventory730/native1177/Windows23/Linux33/macOS32/GUI144Linux140macOS and
Road1038checked/284open/2partial,WS-LF31done/87open remain unchanged.

**W462 compiler, Windows publication and producer regressions (2026-09-23):**
W461 is published as efd5cb72; Preflight35888774668 passed all static contracts.
W459 repairs the actual OpenRaft API, snapshot, authenticated-peer access,
config initializer and frame-exhaustiveness diagnostics from Core35886288492.
Generic cluster configure preserves the bound budget policy and rejects drift
inside both real commit transactions; CLI/GUI strict snapshots retain that policy.
W448 private Windows stages now use capability-relative FileRenameInformationEx
without closing the bound target. Two regressions cover open-target replacement
and an ambient-parent swap. W460 runs the16affected Windows storage/browser cases.
W458 strengthens the real three-chunk producer regression with filesystem-loaded
Block/Replace hooks and captured output/hash/finalization-receipt assertions.
Its producer sink is real; end-to-end Main/Buddy delivery still needs evidence,
so P2-26a stays open. The disconnected synthetic GUI test was removed.
Independent static reviews passed; all executable gates remain hosted/pending.
Inventory730;native1177+Windows23/Linux33/macOS32;Group882;GUI144Linux/140macOS.
Road1038checked/284open/2partial;WS-LF31done/87open unchanged. BSOD hold remains.

**W461 functional acceptance and Omniparser decision (2026-09-23):**
P2-03 is accepted with31required macOS and29applicable Windows identities.
P1-10 has17native+8GUIreducers+2native callbacks; P1-12 has50native and the
real macOS citation callback. Root independently verified complete terminals,
artifact hashes and relevant Gitblob carry to5bace4f0. These are functional
acceptances; original tested commits and unrelated suite failures remain visible.
Crossref/OpenAlex live records are bound; Semantic Scholar429 is noncoverage.
P2-17 has a binding SKIP_FOR_V1_0_REOPEN_ON_EVIDENCE decision grounded in current
upstream, product and Windows/resource evidence. No parser/model was installed.
Preflight5bace35886291287 passed. Core35886288492 passed slim Clippy, then
reported16library/19test-build diagnostics in the new quorum-budget integration;
W459 repairs those actual errors. W448 Windows publication repair has passed
static independent review; hosted behavior is pending. No local executables ran.
Inventory728;native1173+Windows21/Linux33/macOS32;Group878;GUI143/139.
Road1324=1038checked/284open/2partial;286raw/285pre-tag;WS-LF31done/87open.
Evidence: docs/gold-wave451-452-functional-acceptance.md and W457 decision.

**W453 hosted formatting and exact license import (2026-09-23):**
W449 is published as b1fd8466. Its Preflight35885319917 exported formatting for
19 source files; all complete before/after Git blobs, patch SHA256 and source
HEAD were verified before import. No local formatter ran. W446 notice export
35885323058 passed:13 hash bindings, the unchanged original snapshot set and
exactly two OpenRaft0.9.25 upstream additions were verified, then the generated
snapshots and distribution notices were imported. Core35885319425 found W454:
two feature attributes on assignment expressions are unstable on Rust1.91.
The assignments now live in one feature-gated block; fresh hosted proof is pending.
FullCIbc9 finished: macOS17872run/17865PASS/7knownSQLFAIL/25skip; all30native GUI
callbacks passed. P203 containment/vault, W153reasoning and W155citation terminals
are available for criterion-level admission (W451/W452). No Road row closes here.
Inventory723/native1173/Windows21/Linux33/macOS32/Group878/GUI143Linux139macOS;
Road1034checked/288open/2partial;WS-LF27done/91open. BSOD hold remains.

**W449 fixed-voter quorum budget integration; W446/W447 hosted follow-ups (2026-09-23):**
The default-off cluster budget now connects the reviewed domain ledger, real
OpenRaft0.9.25 SQLite storage, authenticated Peeroxide replication/client lane,
fresh membership validation, runtime ownership and each actual provider leaf.
A follower submits once to its known frozen leader; only the first committed
claim produces a local move-only provider permit. Lost replies, partition,
unknown costs and restart retain conservative accounting without a local fallback.
37 focused native tests cover domain, store, three real voters, membership,
transport stop/cancellation and actual paid-leaf admission. Static independent
reviews passed their scopes; hosted compilation and behavior remain pending.
W447 accepts canonical local Windows verbatim-drive roots through the existing
capability walk and adds two Windows-only regression cases; UNC/device refusal
is unchanged. W446 adds exact OpenRaft/macros license snapshot export. The GUI
formatting patch from35883870476 was imported with full before/after blob checks.
Windowsbc9 completed17773tests with19failures:7oldSQL,8browser-root,4WALpublish.
P203 Windows containment passed; macOS continues. W448's unsafe handle-close-only
proposal was rejected and reverted; journal-backed repair remains separate WIP.
Inventory723;native1173+Windows21/Linux33/macOS32;Group878;GUI143/139.
Road1034checked/288open/2partial andWS-LF27done/91open remain unchanged;P2-19open.
No local executable validation; absolute BSOD hold remains in force.

**W444 pinned OpenRaft input admission and GUI syntax follow-up (2026-09-23):**
W439 run35882637851 on4d4f59f5 passed: Rust1.91 compiled the pinned OpenRaft0.9.25
minimal serde/storage-v2 probe. All26 artifact SHA256 bindings and both complete
input/output Git blobs were verified before importing Cargo.toml/Cargo.lock.
The probe covered120 identities, with zero missing/checksum-drift identities;
19 workspace-only packages and32 shared-feature differences remain uncompiled
by this standalone probe. Eight packages are new; production Raft integration
is not yet compiled. Updated distribution notices need the hosted export.
Preflight35882637605 correctly found one excess closing brace in W438 main.rs;
the exact syntax repair removes it. Superseded Core35882647541 was cancelled.
No local executable checks; Road and WS-LF counters remain unchanged.

**W438 GUI Clippy repair and W439 Raft metadata traversal (2026-09-23):**
W437 is published as dbdd81ca; Preflight35881647335 passed all static contracts.
Core35876182651 passed slim Clippy and core test typechecking, then failed the
strict workspace GUI pass with24 diagnostics. W438 repairs only the six affected
GUI Rust files; independent static review passed. No Slint or vendor changes.
W439 fixes the actual graph-report IndexError in35879202289: keep the selected
root separate from the mutable traversal stack. Source, closure, feature and
checksum gates remain unchanged. Both repairs need fresh hosted execution.
Cluster-budget integration remains uncommitted and P2-19 remains open. The
provider leaf now owns quorum admission; follower admission, final integration
review and three-node behavioral checks are still in progress. BSOD hold remains.
Inventory703; Road1034checked/288open/2partial; WS-LF27done/91open unchanged.

**W437 canonical progress-counter repair and reboot recovery (2026-09-23):**
Preflight6afba7c9 run35877975301 passed formatting and metadata, then correctly
rejected the stale canonical PROGRESS WS-LF counter (25/93 versus ROAD27/91).
The canonical count and its stale P1-20 paragraph are now updated to the already
admitted W425/W426 evidence; no new Road checkbox is closed by this repair.
A new workstation boot at2026-09-23 16:57:38 Europe/Berlin is confirmed; cause
remains unproven. No local compiler or product process was observed. The absolute
local execution hold continues; GitHub auth recovered without a new login.
W431 minimal Raft qualification35879202289 failed in the metadata graph report; W439 repairs that workflow. Core35876182651 passed slim Clippy and test typechecking, then reported24 GUI workspace-Clippy errors (W438).
Inventory703;Road1034checked/288open/2partial;WS-LF27done/91open unchanged.

**W430 hosted formatting, W431 minimal Raft qualification and W433 citation results (2026-09-23):**
Citation010d run35874789863 is admitted:50/50 native PASS, all9source/input
bindings and actual ordered terminals verified. Crossref/OpenAlex ordinary CLI
live records have independently recomputed matching claim/record bindings.
Semantic Scholar returned typed rate_limited; successful record coverage remains
unproven. P1-12 stays open for its remaining provider/presentation evidence.
W430 imports only the two source/digest/full-Git-blob-bound hosted rustfmt outputs
from Preflightd083 run35876157640. W428 core/workspaceClippy d083 continues.
W431 corrects the isolated OpenRaft qualification scope: every minimal-probe
identity/checksum must match the exported workspace; feature-unified workspace
extras are explicitly recorded as uncompiled by that probe. Actual production
Raft service/store/carrier/provider integration remains uncommitted and unaccepted.
Inventory703;native1136+Windows19/Linux33/macOS32;Group841;GUI143Linux/139macOS.
Road1034checked/288open/2partial;290raw/289pre-tag;WS-LF27done/91open unchanged.
No local executable validation ran; all compilation and testing remain on GitHub.

**W422/W424 hosted repairs, W425/W426 functional acceptance and W428 lane (2026-09-23):**
Group841bc9 run35871794576 is admitted:841 executed,834PASS,7FAIL; all169
source bindings, matrix/lock and actual ordered terminals match. All seven
failures share an ambiguous SQL ORDER BY transport_identity; W424 qualifies
the existing assignment columns without relaxing predicates or assertions.
W422 groups audit-RPC startup inputs to resolve the actual workspace-Clippy
9/8 argument diagnostic; both feature-gated call sites retain their inputs.
P2-06 is accepted with17Group841+1Group810 Doctor terminals. P1-20 is accepted
with4Group841+8GUI143 terminals; Root checked actual passes and relevant source carry.
W428 adds optional workspace Clippy to the existing CLI-reference lane so the
focused rerun preserves continuing Windows/macOS FullCIbc9 jobs.
W417's first hosted input run35874794184 preserved existing workspace locks
and added8packages, but the separate probe needed its own resolved root lock;
the repair retains exact OpenRaft closure identity/checksum equality before check.
Inventory700; native1136+Windows19/Linux33/macOS32;Group841;GUI143Linux/139macOS.
Road1324=1034checked/288open/2partial;290raw/289pre-tag;WS-LF27done/91open.
Citation010d535c continues; production Raft integration remains uncommitted.
No local executable validation ran; the absolute BSOD hold remains active.

**W417 hosted Raft inputs and W421 citation terminal repair (2026-09-23):**
Citation run35871580933 remains FAILURE:41 actual Rust PASS,9 unstarted;
the runner rejected the interleaved stderr/final-ok form of identity41.
W421 repairs that matcher with seven hosted self-tests before Cargo. Source,
selection50 and three public-provider probes are unchanged; rerun is pending.
W417 qualifies pinned OpenRaft0.9.25 and exports a source-bound manifest/lock
proposal entirely on GitHub. Production dependency and W419 cluster budget
integration remain unpublished and unaccepted. Independent static reviews passed.
Coreef82 is admitted at all4 gates; GUI1438f6 is admitted143/143 with23 bindings.
Group841bc9 and Windows/macOS FullCIbc9 continue. Linux FullCIbc9 failed Clippy;
its exact diagnostics are being repaired separately without cancelling other jobs.
Inventory695; native1136+Windows19/Linux33/macOS32; Group841; GUI143Linux/139macOS.
Road1324=1032checked/290open/2partial;292raw/291pre-tag;WS-LF25done/93open.
The absolute local BSOD hold remains: text/JSON/hash/Git/GitHub operations only.

**W404 citation lane, W411 selection, W413 retry acceptance and W414 format (2026-09-23):**
P2-14 is accepted with19 actual source-bound PASS terminals:17native Group810
and2GUI135; Root verified each terminal and unchanged relevant retry sources.
W404 adds a main-only hosted lane for50 exact citation tests, with correct
integration-harness filters, per-harness compile timeouts and individual receipts.
Its optional three public-provider CLI probes retain typed unavailable results
as noncoverage and recompute every successful claim/record binding.
W411 selects17 existing capability-quality cases for the next group: the old
18/18 receipt cannot settle later producer/WAL dependency changes by itself.
P2-06 remains open; its overlapping Doctor contract already passed inGroup810.
W414 imports only the source/digest/blob-bound two-path formatter output from
Preflightef8235870714177; Coreef8235870714111 continues on equivalent source.
Inventory692;native1136+Windows19/Linux33/macOS32;Group841;GUI143Linux/139macOS.
Road1324=1032checked/290open/2partial;292raw/291pre-tag blockers;WS-LF25done/93open.
No local compiler, formatter, parser, test, product runtime or model download ran.
**W405-W410 recovery, hosted repairs and three functional acceptances (2026-09-23):**
Group810 run35866133454 is source-admitted:810 executed,807 PASS,3 failures;
all163source paths, matrix/lock and ordered individual terminals verified.
P2-01 Dream phases (26), P2-09 research lifecycle (18) and P2-23 Dream opt-in
(12native+10GUI) now satisfy their scoped requirements. W408-W410 retain exact
receipts and relevant-source carry reviews; Root checked all66 terminals.
The three unrelated grouped failures remain open pending W406/W407 rerun.
W406 fixes invalid rollover-fixture JSON and checks the missing journal child
with its NotFound cause; byte preservation and journal retention stay required.
W407 adds seven actual cluster command leaves with honest Unwired GUI gaps,
including the exact inventory-regression expectation. Independent review passed.
Coreed97935866308409 passed all4gates; its bound D9C6E38C CLI reference is imported.
Obsolete FullCI35867787236 is confirmed cancelled; GUI14335867782202 continues.
Next: hosted core readiness, Group824 and replacement full CI for these repairs.
Inventory685;native1136+Windows19/Linux33/macOS32;GUI143Linux/139macOS.
Road1324=1031checked/291open/2partial;293raw/292pre-tag blockers;WS-LF24done/94open.
No local executable validation or model download ran; BSOD cause unproven.
**W392 outbound cluster and W400 session-preview selection (2026-09-23):**
The daemon-owned outbound dispatcher binds exact operator scopes to active
authenticated peers, persists Prepared before enqueue, and permits candidate
failover only after synchronous no-effect errors. Accepted/ambiguous delivery
cannot replay; restart marks unresolved Prepared indeterminate. Results bind
the selected Noise peer and task; late acceptance cannot overwrite Resulted.
The live registry is removed before teardown under the same admission lock.
Ten new cases cover v6-to-v7 migration, scope/CAS/order, restart/correlation,
actual queue/RPC dispatch, authentication and concurrent stop. Final integrated
independent static review passed. Hosted behavior remains pending; P2-18/P2-19
and GUI/Buddy parity are not closed by this source slice.
W400 selects4 existing native and8 existing GUI sidebar-preview cases; no
product or Slint source is changed for it. P1-20 waits their exact terminals.
Inventory676;native1136+Windows19/Linux33/macOS32;Group824;GUI143Linux/139macOS.
Road1324=1028checked/294open/2partial;WS-LF21done/97open unchanged.
No local executable validation or model archive download ran.

**W395 BGE acceptance and W399 WAL test-compile repair (2026-09-23):**
P2-24 is accepted with25/25 required source-bound PASS terminals:16native in
Group780e5,7GUI in GUI135216 and2official-model cases in BGE216. Independent
source-delta review and Root's individual-terminal checks agree; two unrelated
group failures and28unstarted tests remain recorded. See the exact W395 receipt.
Core11835863307776 passed production slim Clippy, then found8 test-only compile
errors in authenticated-leaf fixtures. W399 supplies correct nested-module
imports and keeps the backing bytes alive for logical-frame assertions.
Independent static review passed; the hosted rerun is pending.
The single-path format patch from Preflight11835863308037 was imported only
after source, artifact digest and before/after Git-blob checks. Quality118 passed.
Inventory673;native1122+Windows19/Linux33/macOS32;Group810;GUI135Linux/131macOS.
Road1324=1028checked/294open/2partial;296raw/295pre-tag blockers;WS-LF21done/97open.
No local executable validation or model archive download ran.

**W394 WAL lint repair and admitted GUI135 (2026-09-23):**
Core8ac run35861027738 failed on unused receipt exports/accessors. The narrow,
independently reviewed repair removes unused production surface and retains
the test-only error import; receipt bytes, hashes and proof checks are unchanged.
Its hosted compiler and behavioral reruns remain pending.
GUI135216 run35856964423 is now source-admitted:135/135 PASS, all23 source/input
bindings, ordered selection and actual individual terminals verified. This
includes the six Dream settings cases; later W379 macOS fixtures still need
their own platform proof. Preflightc1 and CodeQualityc1 both passed.
Inventory670;native1122+Windows19/Linux33/macOS32;Group810;GUI135Linux/131macOS.
Road1324=1027checked/295open/2partial;WS-LF20done/98open unchanged.
No local executable validation or model archive download ran.

**W381 core and browser CLI reference accepted (2026-09-23):**
Core216 run35855695782 passed all4explicit gates: slim production Clippy,
core test-target typecheck, CLI build and source-bound reference export.
The imported B6D3EB56 reference adds only browser/status/install. Preflight216
run35855667194 also passed. Group780 will now verify the committed reference.
GUI13535856964423 and BGE235856967745 run on21612331 after test-target success;
this documentation-only import preserves their relevant binary source.
FullCI954 macOS executed17811tests:17797passed/14failed. Ten failures match
the published repairs; W378 confirms two additional browser failures already
have canonical-root fixes in216. W379 handles the two remaining GUI failures.
Windows tests continue; Linux runner-shutdown143 awaits targeted retry.
Inventory657;native1092+Windows19/Linux33/macOS32;Group780;GUI135Linux/131macOS.
Road1027checked/295open/2partial;WS-LF20done/98open unchanged.
No local executable validation ran; see docs/gold-wave381-core-and-reference.md.
**W377 browser archive fixture lifetime repair (2026-09-23):**
Corebb1 run35854299629 passed production slim Clippy, then found one E0505
in the ZIP fixture: ZipWriter's Drop kept its mutable byte-vector borrow
alive at return. A lexical scope now ends after checked finish and before
the vector move. No clone, weaker assertion or production change is needed.
Independent static review passed; hosted compiler rerun remains pending.
Preflightf52 run35854483418 passed all static contracts.
Inventory655;native1092+Windows19/Linux33/macOS32;Group780;GUI135Linux/131macOS.
Road1027checked/295open/2partial;WS-LF20done/98open unchanged.
W373 authenticated compressed-leaf redaction and W374 scoped cluster
assignments are separate unaccepted implementation work, not this commit.
No local executable validation ran.
**W367-W370 Group721 failure repair (2026-09-23):** Source-bound run
35850850940 on954f838a executed all721 selected identities:711passed/10failed;
all153source bindings, matrix/lock and individual terminals were admitted.
W367 removes v45-only objects from historical v41/v42 fixtures and refuses
case-insensitive Dream schema collisions before adding trust columns.
W368 supplies both explicit4096-token fixture budgets without changing
production limits. W369 gives missing managed-browser roots stable error
context and retains no creation/fallback. W370 validates the existing Dream
audit request subtype/payload without minting a second event header; other
audit families remain unchanged. All four repairs passed independent static
review; their hosted rerun is pending. W363 formatting was imported from
source/hash-bound Preflight69 output; no local formatter ran.
Inventory654;native1092+Windows19/Linux33/macOS32;Group780;GUI135Linux/131macOS.
Road1324=1027checked/295open/2partial;WS-LF20done/98open unchanged.
Next: hosted preflight/core, new bound browser CLI-reference import, then
Group780/GUI135/BGE2. FullCI954 Windows/macOS continue; its Linux runner
shutdown(exit143) remains an infrastructure failure awaiting targeted retry.
No local executable validation ran.
**W363 nightly backup and W365 browser lint repair (2026-09-23):**
The public nightly backup and the controlled bare-remote fixture now share
one policy dispatcher. Two new regressions prove both denied modes leave the
home absent and an admitted nightly run produces a verified remote commit,
an archive containing exact WAL bytes but no seeded credentials, and durable
settled state. Independent final review passed, including the owned archive
path required before mutable reads. Twenty-four existing W184 identities
join the grouped selection; its remaining shared and platform/GUI cases
retain their explicit existing lanes.
W365 removes the two actual Coreed749 Clippy diagnostics without suppressions:
a redundant capture and panic-based error extraction. Original install errors
and any cleanup failure remain observable. New hosted verification is pending.
W366 selects the existing CLI-reference equality test; the newly generated
browser command reference must be imported before that behavior run.
Inventory650; native1092+Windows19/Linux33/macOS32; Group780; GUI135Linux/131macOS.
Road1027checked/295open/2partial; WS-LF20done/98open unchanged.
FullCI954 Linux stopped on a hosted runner shutdown (exit143); Windows/macOS
and Group721 continue. No local executable validation ran.

**W362 browser permission type repair (2026-09-23):** Core356
run35851362763 found two Unix capability-permission type errors. The verified
file now uses cap_std Permissions and its extension trait, preserving0700,
the retained handle and the metadata postcheck. Hosted rerun is pending.
Preflight356 run35851360607 passed; source-admitted Core954 passed all4gates.
Group721 and fullCI954 remain active. Inventory648; other counts unchanged.
No local executable validation ran.

**W347/W352 managed-browser install and W355 enabled retention callers
(2026-09-23):** Explicit browser status/install now use the reviewed CFT
manifest, exact archive bytes and SHA, authorized no-redirect transport,
bounded no-follow extraction and identity-confirmed generation publication.
Status reads policy without credential migrations or locks. Default-off
install stops before runtime config/WAL; active install binds its authorizer
to the explicit canonical home and observes Ctrl-C. Browser launch, CDP and
rendered navigation remain open under P2-13.
W355 adds two real enabled CLI/Cron retention caller regressions, including
quarantine receipts and preserved yearly-synthesis inputs. Independent static
reviews passed; 20 new exact identities require hosted execution.
W359 additionally selects12 existing native and6 GUI Dream opt-in/readback
fixtures; P2-23 stays open until their actual passing terminals.
Inventory647; native1090+Windows19/Linux33/macOS32; Group753; GUI135Linux/131macOS.
Core954 run35849819987 passed production Clippy and test-target readiness.
Group721 run35850850940 and fullCI run35850855062 are frozen on954f838a.
Road1324=1027checked/295open/2partial; WS-LF20done/98open unchanged.
No local executable validation or archive download ran.


**W357 hosted test-fixture scope repair (2026-09-23):** Core3978
run35848398917 passed production slim-core Clippy, then found two E0425
errors in test code. The architecture fixture now imports its existing
persist_map function; the v2 retention fixture has a byte-equivalent local
Daily JSONL helper instead of calling a private sibling-test helper.
Production behavior, assertions and watchdogs remain unchanged.
Preflight3978 run35848398949 passed. Hosted test-target rerun is pending;
Group721 and fullCI wait for that readiness. Inventory641; native1058 plus
Windows19/Linux33/macOS32; Road1027checked/295open/2partial; WS-LF20done/98open.
No local executable validation ran.

**W354 hosted Dream lint repair (2026-09-23):** Core32bc run35847289447
reached Clippy and reported four complex SQL row annotations plus three
unused-API diagnostics. Private row aliases preserve SQL/field order; the
unused PhaseComplete enum value and three unused receipt accessors are removed.
Actual completion remains inside the PhaseEffect transaction; receipt contents
and the consumed frame hash stay intact. No suppressions were added.
Preflight1c21 run35847553367 passed. Current compiler/test-target rerun is
pending; Group721 and fullCI remain gated on readiness. Inventory640;
native1058+Windows19/Linux33/macOS32. Road1027checked/295open/2partial and
WS-LF20done/98open unchanged. No local executable validation ran.

**W349 role acceptance and W351 Dream compile repair (2026-09-23):** P2-15
is accepted after all50 required role cases and13 supporting direct-retry
cases passed in source-admitted Group687 run35843153480. Relevant role code
and required fixtures are unchanged; the only mapped-file change is W342's
unrelated reviewed architecture fixture. See docs/gold-wave349-role-enforcement-acceptance.md.
Road1324=1027checked/295open/2partial;297raw/296pre-tag;WS-LF20done/98open.

Preflight76ab run35846507938 passed all static contracts. Core4ea5 found a
missing sixth tuple field and a retained SQLite statement borrowing its
transaction at commit. W351 adds the trust decoder and ends the statement
scope before commit without changing effects. Hosted compiler verification
remains pending. W350 adds two real phase-outbox/WAL delivery fixtures with
ACK-loss restart and no-replay proof. Native1058;Group721;inventory639.
Group721/fullCI wait for test-target readiness.
No local executable validation ran.

**W331/W332/W341/W344 Dream integration and W342/W345/W346/W348 repairs
(2026-09-23):** The opt-in scheduler now prepares bounded, consent-revision-bound
inputs, resumes durable Light/REM/Repair effects and delivers authenticated
append-once WAL audit receipts. Schema45 retains trust through ordinary and
Dream tier movement and real Warm/Cold recall. Phase leases end at synchronous
DB commits; only audit leases span WAL await. Independent integrated static
review passed. Twenty-four new selected identities cover phases, audit,
migration, real Cold reader, existing scheduler rails and Windows chat fixture.
Native1056+Windows19/Linux33/macOS32; Group719; inventory635. Hosted checks
remain pending; P2-01 stays open until its full behavioral acceptance.

Group687 run35843153480 is source-admitted685PASS/2FAIL, all687 terminals and
149source bindings checked. All five W336-W338 repairs passed. W348 repairs
the two remaining Research fixture model/terminal expectations. W342 fixes
Windows graph-generation and lock-snapshot setup; W346 canonicalizes four
macOS fixture roots without changing production no-follow. W345 removes130
unnecessary historic settlement setups while preserving131archives and the
real64/64/2 retention proof under the unchanged watchdog. The old Linux750
unused-unsafe error is already repaired in published supervisor source.
Corec454 run35843801363 passed all four gates with unchanged CLI reference.
The machine-readable Road summary marker is corrected to match the actual
accepted rows:1324total/1026checked/296open/2partial;298raw/297pre-tag blockers.
WS-LF19done/99open. No local executable validation ran.

**W340 response-feedback acceptance (2026-09-23):** P2-28 is accepted with
26/26 native feedback cases from admitted Group684 run35838862993 and5/5
GUI/Main/Buddy cases from admitted GUI129 run35837802269. Required source
blobs are unchanged through fed9196d. Set/replace/remove CAS, exact terminal
targets, privacy-preserving proposal consumption and CLI/Main/Buddy parity
are covered. See docs/gold-wave340-response-feedback-acceptance.md and its
source-bound acceptance JSON. Broader platform and release gates remain open.
Road1324=1026checked/296open/2partial;298raw/297pre-tag blockers;
WS-LF19done/99open. FullCI750 completed: Windows12488PASS/19FAIL/1timeout,
macOS12586PASS/21FAIL. W345/W346 diagnose retained failures; reviewed W342
repairs remain unpublished. Corec454 and Group687 continue on GitHub.
Local BSOD hold remains; no local executable validation ran.

**W333 managed-browser resolver and hosted acceptance (2026-09-23):**
The default-off typed policy and explicit-home resolver now consume W330's
reviewed four-target manifest. No-follow capabilities retain root, directory,
marker and executable identities; hashing uses the bound file, and a future
launcher must revalidate the retained identity. Exact CFT URLs and digests are
checked. No acquisition, launch, CDP or external-rendered route is enabled by
this slice; P2-13 remains open. Independent re-review passed. Seven universal
and one Unix regression are selected: native1032+Windows19/Linux33/macOS32,
Group695, inventory622. W331/W332 remain separate unpublished source work.

GUI1291a17 run35837802269 is fully source-admitted129/129 with23source/input
bindings and ordered actual terminals. W329 Cored6aa35840622919 passed all
four gates with unchanged reference SHA256F7E3604A. W336-W338 Coredecb
35842087666 passed lint and test-target readiness; Group687571b run35843153480
is active. Its repairs and W329 behavior still require that run's results.
Road1324=1025checked/297open/2partial; WS-LF18done/100open unchanged. Windows
fullCI750 completed12488PASS/19FAIL/1timeout of12508executed; macOS continues.
Local BSOD hold remains; no compiler/test/browser/archive execution ran here.

**W336-W339 repairs and three parent acceptances (2026-09-23):**
Group684 run35838862993 on b6090b1f is source-admitted679PASS/5FAIL:
149source bindings, matrix/lock and every ordered terminal verified. P2-08
accepted51/51; P2-11 accepted29/29; P2-12 accepted25/25 plus two previously
admitted unchanged GUI callback/receipt cases. Published source identity is
verified through9cd6f9ab. Three functional parents close; failed aggregate and
platform/release gates remain explicit. See docs/gold-wave339-parent-acceptance.md
and docs/verification/gold-wave339-p{208,211,212}-acceptance.json.

W336-W338 repair all five remaining grouped failures: guarded dispatch count,
real fallback-audit writer, bound retention recovery before inventory, correct
quota-backoff lifecycle count and chained role-error assertion. Independent
source review passed; behavior rerun is pending. W329 Core35840622919 continues.
Dream/WAL/browser source work remains separate until its own review and gates.
Road1324=1025checked/297open/2partial;299raw/298pre-tag blockers. WS-LF18done/
100open. Local BSOD hold remains; no executable validation ran here.

**W329 research dispatch and W330 acquisition (2026-09-23):** Three new
research fixtures drive the real command lifecycle and authorized producer with
an isolated SearXNG fixture. They decode authenticated WAL payloads, bind the
exact topic hash, check terminal order and forbid replay. Independent static
review passed; hosted execution remains pending. Group684 expands to687,
native1022 to1025; no parent checkbox is closed by source review.

W330 run35839698279 on a4194604 passed. Root verified all receipt-file hashes,
GitHub/source identity and four exact CFT154.0.8037.57/revision1689415 targets.
Archive and executable hashes were acquired on GitHub; only JSON/notices and
checksum text reached this workstation. This proves official-TLS acquisition,
not vendor signatures, installation or browser execution. P2-13 remains open.
W331 real Dream effects and W332 dedicated WAL audit are being implemented.
Road1324=1022checked/300open/2partial; WS-LF15done/103open unchanged.
Local executable validation remains prohibited after the reported BSODs.

**W325/W330 managed-browser prerequisite (2026-09-23):** The reviewed
engine decision selects chromiumoxide0.9.1 only as a CDP client after NEOTH's
own contained launch. Externally rendered navigation still requires enforced
browser-wide egress mediation; no runtime, dependency or navigation is enabled.
A reviewed manual main-only hosted lane acquires the exact CFT154.0.8037.57 /
revision1689415 archives for four platforms, verifies bounded ZIP inventory,
and exports only hashes, notices and UTC/GitHub-bound provenance receipts.
This is official-TLS acquisition evidence, not vendor signatures or runtime
acceptance. Hosted acquisition is pending; P2-13 remains open. Inventory611.
Core1a1735837799526 is now source-admitted four-step SUCCESS; Preflightb609
35838777616 passed. Group684b60935838862993, GUI1291a1735837802269 and
fullCI75035833337095 continue. Road/WS-LF counts unchanged. No local executable
validation or browser/archive download ran.

**W318-W323 exact hosted formatting (2026-09-23):** Preflight1a17
run35837779652 produced a three-file format patch. SHA2567F25D287 and every
Git pre/postimage were verified before import. Core1a1735837799526 and
GUI1291a1735837802269 continue on their frozen source; Group684 follows after
test-target readiness. No local formatter or executable validation ran.

**W318-W323 repairs and P2-22 acceptance (2026-09-23):** Group643750
run35833333444 is source/terminal admitted:643executed,624PASS/19FAIL,
138fixture sources plus matrix/lock and every ordered actual terminal checked.
GUI129d6da35831827281 is admitted125PASS/4FAIL, with23source/input bindings;
its overall gate remains failed. Core5bf35835186407 passed all four steps,
including exact CLI reference equality. Hosted preflight5bf formatting was
imported in five files after SHA256 and every Git pre/postimage verification.

P2-22 is accepted: all22 consent/consumer tests passed and all10 relevant
implementation/test sources remain unchanged. Durable grant/revoke ceremony,
default denial, account/sender isolation, revocation quarantine and recovery
are covered. See docs/verification/gold-wave323-p222-acceptance.json.
P2-08 retains51 historical passing tests but stays open for changed provider
sources. P2-11 adds25 missing existing test identities to the next group.

W318 validates the real no-follow quarantine directory before excluding it
from note inventory; foreign file/symlink cases still fail. W320/W321 correct
fixture topology, W322 corrects fixture budget/reload/quota identities. W319
keeps an initially inactive, not-yet-started systemd unit pending under the
existing deadline; READY still requires the complete unit/cgroup contract.
Independent source review passed; all repairs await hosted behavior gates.
Three W318 regressions plus25 P2-11 cases expand Group656 to684. Inventory608;
native1022 universal+Windows19/Linux32/macOS31; GUI129Linux/125macOS unchanged.
Road1324=1022checked/300open/2partial;302raw/301pre-tag blockers. WS-LF15done/
103open. FullCI75035833337095 continues; Linux has a repaired lint plus a
separate runner shutdown, Windows/macOS remain pending. No local executable
validation ran; no workstation crash-cause or overall release claim.

**W315 direct-provider retry (2026-09-23):** Normal nonstream direct chat now
uses the existing fresh-permit retry lifecycle. Typed HTTP401/403 are terminal,
unknown errors remain terminal, known transients are bounded, and a short
explicit Retry-After permits exactly one quota retry; absent/long/repeated
quota signals stop. Consent, role, budget and effect authority are rechecked
before the next raw call. Token cap, compaction, canary, configured fallback
and Claude CLI retain their established behavior; nested authorization rejects.
Recognized OpenAI policy/refusal handling precedes typed status fallback.

Final independent source review passed. Thirteen selected fixtures cover seven
lifecycle/cooldown outcomes, three wrappers and three actual HTTP401 adapters.
Root also corrected nested test-module type qualification before publication.
Inventory601 paths;native1008;Group656 plus2 separate BGE;GUI129Linux/125macOS.
W315 hosted execution is pending. Group64375035833333444, fullCI75035833337095
and GUI129d6da35831827281 continue on their frozen prior sources. No local
executable validation or parent acceptance; Road/WS-LF counters unchanged.

**Hosted milestone on750d162b (2026-09-23):** Core35832269246 is complete
and source-bound: strict slim production Clippy, core test-target typecheck,
CLI build and reference export all passed. The exported reference exactly
matches committed F7E3604A1789839F87DD6A574E3D4987A98E4F4E599CB71179DC32C7ED2D6CFA.
Group643 run35833333444 and full native CI35833337095 were dispatched on750
only after test-target success; both are active. GUI129d6da35831827281 is active.
P2-22's22 required consent/consumer identities are all selected in Group643.
These are running behavior gates, not parent acceptance. No local executable
validation ran; Road/WS-LF counts remain unchanged.

**W316 complete session selection / W317 hosted lint repair (2026-09-23):**
P2-08 now selects all48 original W159 emitter/migration/header/query regressions
plus3W310 live-egress cases. Seven were already grouped;44 additional existing
native identities expand Group599 to643. Native995 and GUI129/125 unchanged.
Core699 run35831257004 stopped at two dead-code diagnostics: the old mapped
intent/result wrappers are now used only by tests, which W317 makes explicit.
Production retains the contextual APIs. Fresh Core remains required.
Preflightd6da35831804454 requested one supervisor-format correction; exact patch
SHA256223C74EB and Git pre/postimages verified before import. GUI129d6da
run35831827281 continues. Inventory600 paths; Road/WS-LF counts unchanged.
No local executable validation, no parent acceptance, no crash-fix claim.

**W314 startup diagnostics and exact hosted formatting (2026-09-23):**
The unresolved Linux crash fixture now reports optional systemd terminal fields
and static helper-stage milestones. Existing required authority fields and
READY/containment ordering remain unchanged; missing diagnostics are explicitly
unavailable. Independent re-review passed. The existing snapshot parser fixture
now covers present and absent diagnostic fields and joins the Linux GUI lane:
129selected=99universal+30Linux. macOS125 remains unchanged.
Preflight699 run35831231907 requested formatting in3W310/W311 files. Exact
patch SHA256B46840C2 plus every Git pre/postimage verified before import.
Core699 run35831257004 continues; GUI129 rerun is next. Inventory598 paths,
native995,Group599; Road/WS-LF counters unchanged. No local executable validation
and no crash-test repair or parent acceptance claimed.

**W310/W311/W312 source and hosted recovery (2026-09-23):**
Accepted channel streams now retain their admission-minted WAL session through
egress intent/result, send, edit and interruption. Three frame-level fixtures
bind recipient/body metadata to the expected session, isolate exact A/B/zero
partitions and cover mapped transport failure. Independent source review passed.
W311 resets stale W153 provider markers and waits for the precise supervised
child slot to clear in W153/W164; production containment remains unchanged.

Core d2 run35829527494 passed production Clippy, then failed five test-target
errors (missing FreedomConfig/Provider imports) and reported two own unused
imports. W312 repairs these exact test imports. Preflight30f35829803010 passed.
GUI128424 run35826461386 is fully source/terminal admitted:128executed,
125PASS/3FAIL,0unstarted;18GUI sources and5inputs verified. Manager-stop127
passed its real isolation checks. W153/W164 fixture repairs await rerun; the
third crash-tree failure remains unresolved and is not claimed repaired.
Admission SHA25663046D7504FDA6814B775EDCFAAF231AD3DD25DEB34C8E9246789D663133CDFA.

Inventory597 paths;native995;Group599 plus2 separate BGE tests;GUI128Linux/
125macOS unchanged. Road1324=1021checked/301open/2partial;WS-LF14done/104open.
No parent checkbox closed and no local executable validation ran. Next: hosted
Core and GUI rerun; Group599/full native CI after test-target readiness.

**W308 exact hosted formatting (2026-09-23):** Preflightd2 run35829527664
requested one runtime.rs format patch. SHA2565AB810E4 plus exact Git pre/postimage
were verified before import. Cored2 run35829527494 and GUI128424 run35826461386
continue; Group596/full nativeCI are not yet dispatched. No local formatter ran.
**W308 adversarial role regression and W309 one-shot repair (2026-09-23):**
Two real sub-agent fixtures prove hostile role/provider/delimiter text stays
in typed data: admitted calls and WAL keep Left; allowed-Right text cannot
bypass denied Left and yields zero raw/request effects. Source review passed.
Corec599 run35828611235 failed three production type errors from one W301
shadowed OneShot handle. W309 retains that handle for terminal audit completion
and role-binds its derived consent authorizer. Preflightb10 run35828902575 passed.
Inventory594 paths;native992;Group596;GUI128 unchanged. Group596/native CI not
yet dispatched; GUI128424 continues. No local executable validation or parent
acceptance. Road and WS-LF counts unchanged.
**W296-W307 exact hosted formatting (2026-09-23):** Preflightc599
run35828610460 requested formatting in14 touched Rust files. Its complete patch
SHA256D224C9EE was verified against every Git preimage/postimage and imported.
Corec599 run35828611235 and GUI128424 run35826461386 remain active. No local
formatter ran; Group594 and native platform CI await core test-target readiness.
**W296-W307 role callers, graph consumers and hosted repairs (2026-09-23):**
The standalone agent fan-out, coding worker/decomposer, direct role/profile CLI,
manual Cron/loop callers and fresh Council-dissent winner retain their actual
configured role at the provider authority boundary. Counted allow/deny, QA,
retry, fallback and WAL fixtures use the production binding seams. Independent
source reviews passed; P2-15 remains open for hosted acceptance.

Architecture recall reads call/import/type evidence from one complete, equal
four-generation SQLite snapshot and reports cycle/evidence caps separately.
Graphify publishes a bounded CODEGRAPH_WITNESS.json tied to its immutable
receipt, CURRENT and wiki commit fence; legacy REPORT/TREE generations remain
readable. Independent source review passed; P2-11 remains open.

Group564452 run35826131329 actually executed556:538PASS/18FAIL, then stopped
on a misnamed W289 discovery. All117 source bindings, matrix/lock and556
ordered terminals were admitted. Eight W289 identities now use their actual
workstream_c_tests module. W304 repairs17 private-home fixture setups; W305
reviews the sole Cron callsite fingerprint drift. Three authenticated fixture
WAL drains now check the inner persistence result as well as the task join.
Corec83 run35827159275 passed production Clippy but found two W292 pinned-future
lifetime errors; W306 scopes those futures before provider/writer teardown.
No failed or unstarted case is accepted.

Inventory592 paths; native990 plus Windows19/Linux31/macOS30; grouped594;
GUI99+29Linux/26macOS unchanged. Road1324=1021checked/301open/2partial;
WS-LF14done/104open unchanged. All executable verification remains hosted.
Next: exact hosted format/Core, Group594, GUI128 and native Windows/macOS CI.

**W298 focused chat preparation lint repair (2026-09-23):** Core424
run35826459440 stopped at one strict Clippy diagnostic: prepare_chat_turn_input
now has9arguments after the daemon role-policy controller was added. The narrow
lint accommodation documents this existing explicit-authority adapter boundary;
no provider behavior changes. Preflight31c run35826643045 is green. Group564452
and GUI128424 continue independently. Fresh Core remains required.
**W292/W293 hosted formatting (2026-09-23):** Preflight424 run35826445977
reported formatting only in chat.rs and chat_child_supervisor.rs. The exact
hosted patch was imported after verifying SHA256 plus both Git pre/postimages.
No local formatter ran. Core424 run35826459440, GUI128 run35826461386 and
Group564452 run35826131329 are active; acceptance remains pending.
**W292 normal-chat roles and W293 Linux containment staging (2026-09-23):**
Normal chat now retains its configured Left origin through direct/fallback calls
and the post-reply authorizer; daemon calls recheck accepted role-policy reloads.
Seven real provider/WAL fixtures cover allow/deny, both fallback leaves and
policy changes after durable request acknowledgment. Source review passed.
The W206 refusal mirror remains terminal; no raw recovery execution is claimed.

Linux containment now stages a fresh cgroup2 mount in a private tmpfs, binds it
over the inherited locked mount, remounts the public top read-only and removes
staging before READY. Provider exec clears capabilities and locks NOROOT.
The selected stop/crash parent fixtures exercise actual capget, NNP, securebits,
mount-denial and reaping checks. Independent source re-review passed; runtime
acceptance remains pending.

Core452 run35825113899 passed test-target typechecking and CLI build/export;
the export exactly matches committed F7E3604A. Production Clippy was skipped
in that run; its separate successful evidence is Core1d6 run35824016472.
Group564 run35826131329 was dispatched on452 before these new changes.
New inventory:573 paths; native967; Group571 plus2 separate BGE cases;
GUI99 universal +29Linux/26macOS =128Linux/125macOS;18GUI source bindings.
Road unchanged:1324 total,1021 checked,301 open,2 partial;WS-LF14done/104open.
No local executable validation ran. Fresh hosted Core, GUI and then native
platform CI remain required; no parent acceptance box is closed.
**W295 hosted fixture type repairs (2026-09-23):**
Core1d6 run35824016472 passed strict slim production Clippy, then found three
test-target errors: two TempDir paths missed path(), and the Cron reload fixture
kept its pinned provider future alive across provider drop. W295 fixes those
exact test-only errors; the ACK-before-reload and zero-raw-call assertions remain.
Preflightfd0d35824727386 and Quality35824726918 both passed. The next Core run
can reuse that production-lint evidence and starts directly at test typechecking.
Manifest571; native960;Group564; other counts unchanged. W292/W293 remain local
work under review; no acceptance or platform execution is claimed for them.

**Canonical Road counter reconciliation (2026-09-23):** Preflight1d6ed46f
run35824016807 reached the release-gate contract and caught a stale dashboard
summary left at1019/303 after the already-evidenced P1-17/P2-05 acceptances.
The published summary and WS-LF rollup now match actual unchanged checkboxes:
1324 total,1021 done,301 open,2 partial;303 raw/302 pre-tag blockers;WS-LF14/104.
No acceptance box changed. GUI1256dae evidence is now fully admitted against
18 source files,5 input bindings and all125 ordered test terminals:123PASS/2FAIL.
Admission: work/gold-20260906/wave293-gui6dae/ADMISSION.json,
SHA2563670FD97A9E8EBEA84D3C3E44411EDA35B3C3E9EB78C0821B76211989C11DB16.

**W294 strict lint and cadence-contract repair (2026-09-23):**
Core62244 run35823363544 exposed three further strict lints after the earlier
type repairs: unused journal display path, a test-only journal loader compiled
in production, and a redundant final return. W294 removes only those diagnostics.
Preflightea31 run35823617595 passed formatting, then found the cadence fixture
still expecting macOS compile100/job140. Its assertion now verifies the published
compile150/job190 budget while retaining one build job and separate execution30.
GUI1256dae completed123/125; W153 fails at inherited-cgroup unmount with EINVAL,
W164 exits before provider startup without a captured underlying cause. Both
remain unaccepted. Manifest570; other inventory/road counts unchanged.
No local compiler, formatter, parser, tests or runtime were used.

**W289/W290 hosted formatting follow-up (2026-09-23):** Preflight62244
run35823362619 produced only Cron-runner and retention-read formatting changes.
Both exact pre/postimage Gitblobs and the artifact SHA256 were verified before
import. Core62244 run35823363544 and GUI1256dae remain active. Parent acceptance
stays open; grouped564 and platform CI follow the Core test-target check.

**W289 Cron role binding and W290 hosted retention repair (2026-09-23):**
Cron now treats provider, model, fallback and explicit role as job-local provider
intent. Active role policy requires an explicit origin; model-only and role-only
jobs build a bound topology, and the daemon scheduler passes its accepted reload
controller to the final provider authorizer. Eight actual resolver/provider/WAL
fixtures cover admission, rejection and the policy reload before raw send.
Independent source re-review passed. P2-15 remains open.

Core86fef run35822418284 failed before behavior execution: one reference-depth
comparison, two unconstrained record vectors and an unformatted independent-if
lint. W290 repairs those exact diagnostics and preserves underlying NotFound
through contextual retention reads, so existing missing-note recovery can run.
The exact five-file hosted rustfmt patch from Preflight35822403521 is imported.
W280/P2-04 remains unaccepted until hosted behavior passes.

Inventory569 paths; universal native960; platform extras Windows19/Linux31/macOS30.
Grouped selection564; GUI98+27Linux/26macOS unchanged. Road1324 =
1021 checked/301 open/2 partial; WS-LF14 done/104 open.
FullCIce0 attempt2 ended with runner shutdown/exit143 during Workspace Clippy,
after about8m46s of its30-minute step budget. No Rust/Clippy diagnostic supports
a source repair. GUI1256dae run35820987854 is still active.
No local executable validation ran. The next gates are fresh hosted Core,
then Group564 after test-target typechecking, followed by the full platform CI.


**W280 retention implementation and W288 macOS budget (2026-09-23):**
W280 introduces explicit default-off Daily retention execution v2. Settlement
receipts bind owned notes to exact file objects; archives and notes quarantine
on their own filesystem. Durable effect/purge journals reconcile the actual
pre/post-rename and pre/post-unlink states. Committed receipt mismatches fail
without rewriting evidence; terminal purge retries preserve their receipts.
Yearly synthesis retains Daily period inputs, unions active archives, filters
valid non-Daily records, and preserves canonical writer-generated JSONL digests.
Independent source review and subsequent exact recovery corrections are recorded
in docs/gold-wave280-daily-retention.md. This is implementation, not acceptance.

The hosted selection adds51 exact cases:17 new v2 behavior/recovery/provenance
tests,2 authority-schema tests,2 object-bound rename tests (one Unix), and30
existing hygiene/Jaccard/synonym/migration/CLI/cron cases. The concurrent yearly
fixture was already selected. Grouped count556; universal native952; platform
extras Windows19/Linux31/macOS30; manifest567. GUI counts remain98+27/26.

Group5048afd35820382140 is fully source-bound:504 executed,503 passed,1 failed;
all109 source bindings, matrix/lock and ordered terminals match. All13 W279 cases
and both actual W285 provider/WAL cases passed. The sole failure was the raw
provider-callsite inventory fingerprint after the reviewed Left-role binding.
It still finds one authorized background effect edge; the expected fingerprint
is updated from that exact hosted diagnostic, without relaxing the invariant.
Core8afd35820395597 passed Clippy, test-target typecheck, public CLI and export.

FullCIce0 attempt1 macOS timed out after100 minutes while actively compiling;
no Rust diagnostic was reported. W288 raises only macOS compile150/job190
minutes, retaining one build job and the separate30-minute execution window.
Only Linux's runner-communication failure was rerun as attempt2; preserve it.
Preflight6dae's exact two-file formatting patch is imported and source-bound.
Road remains1324=1021 checked/301 open/2 partial; WS-LF14/104. P2-04 remains
open until the actual hosted behavior gates pass. No local executable ran.

**W286/W287 hosted-platform repair and exact CLI export (2026-09-23):**
GUI125b7ca is fully source-bound:125 executed,123 passed, W153/W164 failed.
W286 replaces the inherited cgroup mount after private propagation, then mounts
inside the new cgroup namespace and makes that mount read-only. The required
root=/, readonly and nsdelegate checks still precede provider/guardian readiness.
Independent source review passed after adding the syscall safety justification;
hosted GUI acceptance is pending. Its Linux plan identity was renamed, not added.
The supervisor source is now explicitly included in the GUI receipt binding set.

FullCIce0 Windows ran17595 tests with3 failures: doctor count63vs64, JSON-escaped
Windows grep paths, and the pre-preview import method name in a source contract.
W287 repairs these exact assertions; production behavior is unchanged. The Doctor
case joins grouped selection505; the integration contract is explicitly required
in full CI. FullCIce0 macOS remains active and is preserved.

Coree700 run35819233475 passed slim Clippy, test-target typecheck, public CLI build
and export. Its exact CLI reference (SHA256 F7E3604A1789839F87DD6A574E3D4987A98E4F4E599CB71179DC32C7ED2D6CFA)
is imported, adding the native fs glob command. Preflight8afd supplied the exact
bg_session/fs formatting patch; its pre/postimages were verified and W287's
independent grep hunk preserved by replay comparison.
Inventory563 paths/911 universal native identities; grouped505; GUI125 Linux
with18 explicit GUI source bindings. Road1021/301/2 and WS-LF14/104 unchanged.
W280 remains uncommitted while its actual recovery/provenance fixtures are reviewed.
No local executable validation ran; no new Gold checkbox is closed.

**W285 background role binding and W279 fixture repair (2026-09-23):**
The detached background worker now carries its configured Left-role authority
through the existing final provider authorization. Two new fixtures use the actual
AuthorizedProvider and WAL authorizer: allowed model reaches one leaf and records
a request; disallowed model reaches zero leaves and writes no request event.
P2-15 remains open beyond this consumer. Hosted validation is pending.

Group502 run35818252940 at7f84dbdc is source-bound:502 executed,500 passed,
2 failed,0 unstarted; all109 source bindings and ordered terminals verified.
The two failures were the replace-hook expectation and a zero-deadline constructor
unwrap. Both fixtures are repaired without changing production glob behavior.
Preflighte700's exact one-file format patch is imported; Coree700 passed slim
Clippy and test-target typecheck and is still building/exporting the public CLI.
GUI125b7ca executed125 with123 passed and W153/W164 failed. W153 reports EBUSY
at the fresh cgroup2 mount; W164's narrower cause remains unproven.
W280 stays unpublished while yearly-input, rename-identity and crash-recovery
defects and real recovery fixtures are repaired. FullCIce0 remains active on macOS;
Windows failed and Linux lost runner communication. No replacement FullCI dispatch.

Inventory:561 paths,910 universal native identities; platform extras unchanged
(Windows19/Linux30/macOS29); grouped selection504, plus two separate BGE tests.
GUI98 universal plus Linux27/macOS26; Linux selection125.
Road remains1324 =1021 checked/301 open/2 partial; WS-LF14 done/104 open.
No local executable validation ran. No additional roadmap item is accepted.

**P2-05 Self-improve quality accepted (2026-09-23):**
Group489 run35816919838 passed489/489 atb7ca8bf4 with all107 source bindings,
matrix/lock and ordered terminals admitted. This includes the four passive
Buddy-quality cases and W278's exact retry-role denial receipt. W275's nine
Core/CLI cases are also admitted from Group484. Seven GUI quality fixtures
at GUI8f16 positions23–27,105–106 passed: quality projection/refusal, exact
accept/readback and passive Buddy handoff. GUI8f16 as a whole remains122/124;
its W153/W164 failures are outside this specific quality acceptance.

The six Core/GUI dependency blobs are unchanged fromb7ca to7f84. Relative to
GUI8f16, main.rs changed only unrelated W274/W155 test helpers; the production
quality path and all seven accepted quality fixtures are unchanged.
P2-05 is closed. Road1324 =1021 checked/301 open/2 partial; raw blockers303,
release-tag blockers302; WS-LF118 =14 done/104 open. This does not claim live
provider QA, packaged GUI acceptance or overall release readiness.

**W284 exact hosted formatting and Clippy repair (2026-09-23):**
Preflight7f84 exported a four-path rustfmt patch. Root verified the run HEAD,
artifact hashes and exact Git preimages/postimages before applying it.
Core7f84 then reported seven diagnostics in three classes: nonminimal Boolean
conditions, the nine-argument glob helper and two collapsible conditionals.
The repair names the forbidden-pattern predicate, groups the two discovery
limits in GlobBounds and uses let-chains; no lint is suppressed. One unnecessary
test-DB mutable binding is removed. Runtime admission awaits fresh hosted gates.
FullCIce0 Linux failed from hosted-runner communication loss during workspace
Clippy, after slim Clippy passed; CPU/memory/network cause is unproven. Windows
and macOS continue, and that run is preserved. No local executable work ran.

**W279 native glob source batch (2026-09-23):**
Native fs glob now enumerates bounded, sorted names through a separate
OsDirectoryList permission and retained no-follow directory capabilities.
Required audit and typed hooks precede enumeration; cancellation/deadline
are checked through the final response. Optional indexed symbol sidecars
revalidate root identity, complete snapshot and generations after SQL.
Windows uses the retained HANDLE FileIdInfo identity; Unix uses dev/inode.
Rooted or drive-prefixed glob patterns are refused on all platforms.

The source review covered actual caller ordering, Windows API definitions,
root replacement and freshness refusal. Thirteen hosted cases are selected:
eleven new tests (ten universal, one Unix) plus existing exhaustive action
and IFC mappings. Grouped selection502; universal native908; platform extras
Windows19/Linux30/macOS29. GUI125 and Road1020/302/2 remain unchanged.
Hosted formatting, compilation and behavior are pending; no local executable
validation ran. W280 recurring Daily retention is a separate in-progress batch.

**W277 Doctor accepted; W275/W276 hosted proof (2026-09-23):**
Group484 run35815551129 passed all484 exact tests on2b0c6f30. Admission binds
106 source paths, matrix/lock and every ordered test terminal. W275's actual
CLI stage/review/exact-digest accept/readback and corpus-drift refusal passed;
W276's existing-run resume/receipt/lock/revocation fixture passed.

P1-17 is closed for authenticated channel/account transport-health diagnosis:
Discord, Signal, the actual Doctor caller, cross-account/channel isolation,
thresholds, incomplete evidence and tampered/unreadable WAL are covered.
All13 production dependencies remain byte-identical through b7ca8bf4.
Provider-usage attribution and recipient delivery are outside this acceptance.

Core3903 run35816349028 passed slim Clippy, core test-target typecheck,
public CLI build and reference export. Its exact generated resume-status
reference is imported (SHA25685d02ff6). Group489b7ca and GUI125b7ca remain
active; FullCIce0 is preserved. Road1324 =1020 checked/302 open/2 partial;
raw blockers304/release-tag blockers303. WS-LF118 =13 done/105 open.
W279 is under final source review; no local executable validation ran.

**W281 actual Linux containment repair (2026-09-23):** GUI8f16 is fully
admitted at122/124, with17 source bindings and all124 ordered terminals; no
fixture was unstarted. The exact production helper receipt binds HEAD, path,
542666952bytes and SHA91ef5a50. W153 reaches the fresh cgroup2 read-only mount
and returns EBUSY; W164 reports inactive/dead with empty helper stderr, so no
more specific W164 cause is asserted.

The Linux helper now first mounts its namespace-root cgroup view without
changing the shared superblock to read-only, then applies read-only at the
private VFS mount with MS_BIND|MS_REMOUNT. Both operations fail closed before
provider launch, and final root/ro/nsdelegate checks remain mandatory.
Independent source review passed. One Linux-only flag/order fixture makes
GUI125 =98universal+27Linux (macOS remains26 extras). W278's exact one-file
hosted formatter receipt is also imported. Core3903 slim Clippy passed;
its test-target check/export and fresh native/GUI behavior remain pending.
Road and WS-LF checkbox counts are unchanged; no local executable work ran.
**W278 retry receipt and W276 lint repair (2026-09-23):** the Claude tmux
immediate-before-send role recheck now retains the typed authorization-denied
receipt for an admitted retry. The real helper/lifecycle fixture binds a
nonempty chain, attempt, class, provider and wire model, with no extra terminal.
Independent source review passed; tmux transport execution is not claimed.

Core2b0 stopped at Clippy because an eight-argument function carried a lint
expectation despite the repository threshold being eight. The unnecessary
expectation is removed; no warning is suppressed. W275 also selects the four
existing passive Buddy quality/provenance regressions. Grouped selection is
489 and the universal native inventory is896; GUI124 and all Road counts are
unchanged. Core and focused runtime validation of these changes remain hosted.
**Hosted follow-up (2026-09-23):** Group4654162 run35813951622 passed all
465 exact tests, including both W273 acknowledgement-gated cancellation cases.
Admission verifies every terminal, all103 source paths and matrix/lock against
Git blobs at4162c45b. The three-path W275/W276 formatter receipt from run
35815539018 on2b0c6f30 is imported after exact source/preimage/postimage/hash
checks. Core2b0 and Group4842b0 continue on their original bound source. No
local formatter, compiler, parser, test or runtime was used.
**W275–W277 CLI acceptance, recall resume and Doctor qualification (2026-09-23):**
W275 exercises real self-improve staging, review, exact-digest acceptance and
accepted readback. Its separate corpus-drift leg calls review first and proves
acceptance refusal without changing the target, proposals or ledger. Evaluator
and audited approval use the existing hermetic core path; full CLI Execute
provider QA is not claimed. Independent source review passed.

W276 adds the read-only recall-parity resume-status command. Existing run,
anchor custody, four-grader plan, attested results and receipt are revalidated;
missing inputs, revocation, malformed receipts and an active writer cannot
produce report readiness or create artifacts. The existing lock is opened,
never created, and custody/artifacts are rechecked after receipt verification.
Independent final review passed. This reports readiness for a separate manual
gate report, not a parity pass. The P1-08 parent remains open.

W277 selects nine additional account-health tests beside the already-selected
equal-account-name case and actual Discord/Signal/Doctor callers. This qualifies
authenticated transport-health diagnosis; provider usage attribution and
recipient delivery are not inferred. Grouped selection is now 484; native
inventory is 895 universal identities. Hosted execution of these changes is
pending. Road remains 1324 = 1019 checked / 303 open / 2 partial, with 305 raw
and 304 release-tag blockers; WS-LF remains 12 done / 106 open. GUI124 and the
active FullCI ce0ecba2 are preserved. No local executable validation ran.
**W270 Hippocampus accepted; Group465 all green (2026-09-23):** P2-02 is
closed from eleven actual passing tests, including WAL-indexed importance
through the accepted task tick to CLI readback, threshold/idempotency, rejected
reload, Custom refusal, retention rollback and both migration outcomes. Root
verified all 103 Group465 source bindings, matrix/lock and 465 individual terminals;
the ten production dependency files remain unchanged through 4162c45b. An
independent review confirmed the complete runtime path. W269 readiness and W271
actual Doctor caller also passed in this run. Wider channel/CRG/release rows
remain open. Road 1324 = 1019 checked / 303 open / 2 partial; raw blockers 305 and release-tag
blockers 304. WS-LF 118 = 12 done / 106 open. Inventory 540/884/98 and Group465/GUI124
remain unchanged. The exact two-path hosted GUI formatter receipt is imported;
no local executable validation ran.

**W273/W274 deterministic platform fixtures (2026-09-23):** the two provider
cancellation tests now use the existing one-shot provider-error acknowledgement
gate. Each requires the real cancellation terminal to become durable, proves
that dispatch is still pending while acknowledgement is withheld, then releases
the gate and verifies full settlement plus matching nonempty invocation IDs.
This replaces a250ms whole-disk-roundtrip assertion with explicit ordering;
production cancellation, terminal durability and no-retry behavior are unchanged.

W274 preserves the W153/W164 macOS fixture identities while exercising the
explicit unsupported-containment refusal: no child start, no invocation, no
success repaint and no feedback availability. Linux success checks remain.
W155 waits for actual proof-bearing lookup execution and private stdin content,
then terminal UI state, retaining exactly-once approval and no-proof negatives.
These fixtures require fresh hosted execution; they do not claim macOS legacy
child support. Source/test counts and Road1018/304/2 are unchanged.

The W274 source was published early in a25658ea by the delegated reviewer;
Root stopped further delegated Git changes and cancelled its duplicate GUI run
35813705858. The intended GUI8f16run35813667946 remains active. Root rechecked
and binds the published source in the canonical inventory here; no force push,
source loss, local compiler, tests or runtime activity occurred.

**W272 Linux production helper entry (2026-09-23):** the hosted containment
fixtures now build and launch the real `neothd-gui` executable through its early
internal-helper entry, before runtime/GUI threads. The former libtest helper
entry ran namespace setup inside harness thread state; the actual W153 error
was `unshare(...): EINVAL`. Production namespace flags and all systemd checks
remain unchanged. Both GUI harnesses share the explicit validated helper;
missing build/discovery/receipt/profile setup fails before fixture execution.
Cargo artifact selection uses `profile.test=false`, with exact binary name/kind,
source HEAD and executable hash/size receipt. Independent source review passed;
a fresh hosted run must prove the fix. GUI124 and Road counts remain unchanged.

Group451cbae35812250221 is fully admitted at451/451 with99source bindings,
matrix/lock and every actual terminal. Corecbae35812252104 passed slim Clippy,
core test-target typecheck, CLI build and reference export. Its SHA-bound CLI
reference remains identical to the committed file. W268 Signal is therefore
focused-native validated; unrelated all-platform/release work remains open.
The matrix sourceInputs count is synchronized to its540actual manifest entries.

**Hosted GUI/FullCI failure evidence (2026-09-23):** GUI841 run35810916881
is fully admitted at122/124 (17 source bindings, 276 artifact hashes, every
ordered terminal). W153 now exposes the actual helper syscall failure:
`unshare user/cgroup/mount/PID namespaces: Invalid argument (os error 22)`.
W164 has empty helper stderr and no independently bound exit125 record.
There is no matching AppArmor DENIED. The fixture currently enters the helper
through Rust libtest rather than the production early-main path; W272 is
repairing that test launch using the actual production executable while keeping
all namespaces and systemd containment checks mandatory.

FullCI49 run35805037288 has completed. Windows passed17,575/17,576 (24 skipped)
and macOS17,658/17,663 (25 skipped). macOS failed two chat cancellation fixture
assertions, W155 citation proof-file readback, and W153/W164 legacy-child startup
on the explicit fail-closed unsupported macOS containment path. These are
individual test failures, not runner/job timeouts. Fresh current-source platform
validation and the GUI repairs remain required; no release acceptance is claimed.
The W269/W271 hosted formatter receipt was verified against all three exact
source pre/postimages. Road counts are unchanged; no local executable work ran.

**W269/W270/W271 combined native batch (2026-09-23):** explicit native
`fs read`/`fs grep` enrichment now exposes bounded optional readiness in JSON
and Table output. Existing admission, retained-file reads and no-hit sidecar
suppression stay intact. The post-read check distinguishes actual stale identity,
generation/completeness/freshness evidence from unavailable optional data.
CRG-05 remains open; source review passed and hosted validation is pending.

W270 selects eleven existing Hippocampus tests for P2-02 after independent
review confirmed the real WAL-index -> accepted task tick -> transaction -> CLI
path. W271 adds the actual Doctor caller over one authenticated WAL containing
failing Signal and healthy Discord records from sealed production emitters.
Neither pending validation closes a Road item. The combined selection is now
Group465, with 540 source paths, 884 universal native identities and GUI124;
platform extras and Road1018checked/304open/2partial remain unchanged.
The W268 hosted formatter receipt was verified and imported in e97bd4cc;
Preflight35812376262 passed. All executable validation remains GitHub-hosted.

**W268 Signal default reply evidence (2026-09-23):** the actual default Signal
receive-to-reply path now records authenticated intent before its adapter call
and terminal evidence afterward. Startup alone mints its sealed `signal/default`
identity after URL, local number, exact allowed E.164 sender and provider checks.
The strict historical collector and Doctor preserve channel/account isolation.
Three new caller/Doctor fixtures plus three existing grouped identities cover
intent refusal, adapter success/error, accepted effect with failed receipt and
no retry, generated authenticated WAL and equal account names across channels.
Independent source review found and corrected fixture binding and visibility
issues. Hosted validation remains pending; P1-17 stays open. Inventory is now
540 source paths, 881 universal native identities, Group451 and GUI124; platform
extras unchanged. Road remains 1324=1018 checked/304 open/2 partial.

FullCI49 Windows completed 17,576 tests: 17,575 passed, one failed and 24 skipped.
The old source fails its first Context status-envelope assertion; W257 af0e056f
fixes that assertion and W264 e802d74a separately fixes paused-plan refusal.
Neither correction has a fresh Windows pass yet. macOS tests remain active;
no replacement full-CI run is dispatched while that job is running.
Local compiler, formatter, parser, tests and runtime execution remain prohibited.

**Group448 accepted (2026-09-23):** hosted run35809861844 on e802d74a passed
448/448 exact native fixtures. Root verified all98source paths against the
selected Git blobs, matrix/lock inputs and every individual passing terminal.
The real Unix Context Import Status/Plan/Apply/Pause/refusal/Resume/reopen/shutdown
roundtrip now passes. All seven Discord sender/provenance/collector/Doctor cases
pass, including accepted effect with a failed receipt writer and no retry.
This is focused native evidence; W153/W164 GUI startup and all-OS/release gates
remain separate. Core0fb35810433910 passed slimClippy, test-target checking,
CLI build/export; its SHA-bound reference matches the committed snapshot.
The one-path W267 hosted formatter receipt was verified and
imported. Inventory and Road counts remain unchanged; no local execution ran.

**W267 GUI diagnostic capture correction (2026-09-23):** GUI124a8 reached
the same W153/W164 helper exit125 before provider startup. W260 appended the
bounded helper stderr to a UI error that was then truncated, so the actual
operation still was not observed. W267 writes the bounded diagnostic directly
to Linux-test stderr and returns the original activation error unchanged.
No production containment rule, timeout, provider launch or fixture requirement
is weakened. Fresh hosted GUI evidence remains required; Road counts unchanged.

**W265 silence-watchdog acceptance (2026-09-23):** P1-21 is accepted from
13 actual native terminals plus one GUI timeout-presentation terminal. Root
verified all seven native caller/consumer files and the GUI presentation source
are unchanged through0fb6c307; an independent review confirmed real pipeline
progress wiring, 120-second silence semantics, cancellation races and visible
typed retry guidance. No whole failed run or unrelated feature was accepted.
P1-20 remains open under its explicit all-OS/current-candidate release gate.
Current Road1324=1018checked/304open/2partial;WS-LF118=11done/107open;
raw blockers306/release-tag blockers 305. No local executable validation ran.
See `docs/gold-wave265-watchdog-acceptance.md` and
`docs/verification/gold-wave265-watchdog-acceptance.json`.

**W262 Discord evidence / W264 actual paused-import refusal (2026-09-23):**
The real default Discord Gateway reply sender now records an authenticated,
account-bound intent before its adapter call and a terminal result afterward.
Its closed startup provenance, historical WAL collector and Doctor keep
`discord/default` separate from same-named Telegram/Slack accounts. Caller
fixtures cover missing intent, adapter error, accepted delivery and an accepted
effect whose result writer fails, without retry or hidden success. Seven exact
native identities are selected; wider channel/account-map coverage stays open.

Group441 `35808222289` on `85c87f57` is admitted at440/441 with93source paths,
matrix/lock and all actual terminals verified. W256 search, W257 Doctor and
W258 socket repair passed. The sole failure occurred after successful import
Status/Plan/Apply/Pause: the fixture incorrectly unwrapped a paused Plan's
expected HTTP422 client refusal as success. W264 fixes both Unix and Windows
fixture expectations while preserving production rejection and the subsequent
Resume/reopen/shutdown assertions. Fresh execution remains required.
Inventory539sources/878universal native/98GUI; Group448/GUI124. Native extras
remain Windows19/Linux29/macOS28. Road1017checked/305open/2partial is unchanged.
Core70ef `35808923302` passed slimClippy, test-target checking and CLI build/export.
Its source/SHA-bound reference now documents `fs grep` and is imported; W262/W264
Group448 one802 remains pending. Coree802 rejected a public constructor
exposing crate-private provenance; W266 makes that daemon-only constructor
crate-private, preserving the sealed authority. Fresh Core validation is required.
GUI124a8 still runs
with bounded test-only helper diagnostics. No local executable validation ran.
See `docs/gold-wave262-discord-channel-flapping.md` and
`docs/gold-wave264-paused-import-fixture.md`.

**W260 startup diagnostics / W261 throughput accepted (2026-09-23):**
P2-29 is accepted from its 12 native/CLI/daemon and seven GUI/Main/Buddy
individually passing, source-bound terminals on `d99d5c6c`. The display uses
actual visible stream events/s and rejects invented live token rates. Relevant
source paths were unchanged through `c43e5d0e`. This does not accept either
whole failed run: Group432 remains 430/432; GUI124 remains 122/124. W153/W164
still fail before provider launch with service exit125; P2-28 remains open.
W260 preserves already-buffered helper stderr only in Linux test builds, after
failed activation cleanup, with one nonblocking read capped at4096bytes.
Production containment and successful stream handling are unchanged.
Coreaf0 `35807294240` passed slimClippy, test-target checking and CLI export;
the SHA-bound CLI reference matches the committed snapshot. W256/W258 core
Group441 on `85c87f57` remains pending. Its Core run failed the strict
nine-argument helper lint; W263 groups cancellation and timeout without a
lint waiver or behavior change. A fresh Core run is required. Hosted rustfmt was imported
with exact source/SHA/preimage/postimage verification; no local formatter ran.
Current Road:1324 leaves,1017checked/305open/2partial; WS-LF10done/108open;
raw blockers307/release-tag blockers306. No release qualification claimed.
See `docs/gold-wave260-gui-child-start.md` and
`docs/gold-wave261-live-throughput-acceptance.md`.

**W256 native search and W258 Unix fixture repair (2026-09-23):**
`neoth fs grep` adds bounded literal search over one allowlisted UTF-8 file,
using the existing retained-descriptor read admission. Results carry line
numbers, explicit empty/truncated states and UTF-8-safe snippets capped at
512 bytes including ellipses. Optional default-off codegraph enrichment is
path-outline evidence only; no hit drops both sidecars. Five regressions include
the actual caller context and its consumed once guard. CRG-05 remains open.
W258 holds original and replacement Unix socket listeners through the identity
assertion so immediate inode reuse cannot invalidate the fixture. Production
identity checks are unchanged; same-EUID ABA protection is not claimed.
Independent static review passed. Hosted execution of both changes is pending.
Inventory: 538 source paths / 871 universal native / 98 universal GUI;
Group441 / GUI124, platform-native extras Windows19/Linux29/macOS28 unchanged.

Group432 `35806200712` on `d99d5c6c` is admitted at 430/432 passing with all
92 source paths and exact terminals bound. Its failures are the Unix socket
fixture repaired here and the actual status-envelope assertion already repaired
in W257. GUI124 `35806202796` finished with failure; exact receipts are under
review. Core `35807294240` on `af0e056f` passed slim Clippy and test-target
checking; CLI export is pending. FullCI `35805037288` still runs its Windows
and macOS tests; its Linux lint failure was repaired in `d99d5c6c`.
No local compiler, formatter, parser, test or runtime ran. Road remains
1324 leaves: 1016 checked / 306 open / 2 partial; no release claim.
See `docs/gold-wave256-native-search-enrichment.md` and
`docs/gold-wave258-unix-socket-fixture.md`.

**W257 authenticated Context Import Doctor (2026-09-23):** Doctor now reads
live daemon control-plane status through the existing authenticated Context
client. It reports status availability, pause/revocation, missing accounts or
unavailable transport without claiming an import succeeded. Malformed, duplicate,
zero-revision and unknown lifecycle data fail with content-free details.
List/explain remain static; no repair, import or config-derived Ready is added.
Review caught and corrected the raw success-envelope mismatch: the production
writer returns `{ok:true,data:{accounts:...}}`. Doctor and both existing actual
Windows/Unix client assertions now use that real wire form; product wire behavior
is unchanged. No temporal-staleness claim is inferred from absent timestamps.
Four native regressions are added. Inventory: 538 sources / 866 universal native /
98 universal GUI; Group436 / GUI124; platform extras remain 19/29/28 native.

Core `35805832718` on `3427d4b0` passed slim Clippy, test-target typecheck and
CLI build/export. Its exact SHA-bound reference matches the committed snapshot.
The current Group432/GUI124 runs on `d99d5c6c` remain pending; the status-assertion
correction here still needs actual execution. FullCI49 W186 live-audio receipts now bind 19/19 passing hermetic fixtures
on each of Windows, Linux and macOS, with five source paths and exact terminals.
This does not establish real hardware, provider, package or release qualification. See `docs/gold-wave257-context-doctor.md`.
Road counts stay unchanged and the absolute local BSOD hold remains active.

**W251 Hosted acceptance (2026-09-23):** Group424 `35805034886` on `49e58dfb`
passed **424/424**. All 91 selected source paths, matrix, lock and every actual
test terminal were verified. The previously failing held-lease lifecycle case
now passes without a larger timeout. This proves the W247/W251 focused native
batch at that source; it does not cover later W249/W253 additions or close the
broader CC-03/CC-04 criteria. The one-path W253 formatting receipt from
Preflight `35806201049` was source/SHA/preimage/postimage verified and imported.
Group432 `35806200712` and GUI124 `35806202796` continue on `d99d5c6c`.
No local formatter, compiler or test ran; Road counts remain unchanged.

**W253 import preview and W255 actual-guardian gate (2026-09-23):** import
planning now returns the exact retained plan's record count, policy revision
and parser revision beside its opaque confirmation tokens. It exposes no source
content or identity and leaves the confirmed re-read/commit path intact. A new
universal regression checks a multi-record preview without a receipt effect;
existing Windows/Unix actual daemon roundtrips check the exact response allowlist.
Independent review passed after limiting the unused legacy wrapper to tests.
Inventory: 537 sources / 862 universal native / 98 universal GUI; native extras
Windows 19 / Linux 29 / macOS 28; Group432 / GUI124. CC-04 remains open.

W252 GUI124 `35805521658` bound all inputs but ran no builds/fixtures: the exact
profile was loaded, while util-linux failed at
`setgroups`. W255 retains required manager/bus readiness and exact harness
profiles, and uses the mandatory W153/W164 product guardian fixtures as the
namespace acceptance gate. The mismatching synthetic util-linux prerequisite
is removed; actual fixture failures retain bounded kernel/manager diagnostics.
No production containment check or fixture selection is weakened.

Core `35805267468` failed on a Unix-gated trait import and an unused `mut`.
Both were corrected in `3427d4b0`; Preflight passed and Core `35805832718` is
running. FullCI `35805037288` on the earlier `49e58dfb` milestone exposed one
`manual_contains` lint in the pinned OpenClaw inventory test; the equivalent
`contains` expression is corrected here while the remaining native jobs run.
See `docs/gold-wave253-context-next-boundary.md` and
`docs/gold-wave255-actual-guardian-gate.md`. Road counts remain unchanged;
all executable validation stays on Hosted runners under the local BSOD hold.

**W252 scoped Hosted AppArmor prerequisites (2026-09-23):** the confirmed
`unprivileged_userns`/`sys_admin` denial is addressed with temporary profiles
attached only to `/usr/bin/unshare` and the exact Cargo-reported GUI harness
executables. Explicit user-namespace permission preserves the production
containment requirements; complain mode retains ordinary runner access for
those exact executables. No global AppArmor/sysctl setting or product check
changes. Profiles are registered for cleanup before receipt copy. Independent
review passed after repairing YAML heredoc indentation and cleanup ordering.
The actual GUI124/W153/W164 outcomes remain pending. W249's exact two-path
Hosted formatting patch from Preflight `35805266961` was bound and imported in
`af8c7c82`; its Core `35805267468` continues on `b47f1520`. FullCI and Group424
continue on the earlier W251 milestone `49e58dfb`, without replacement dispatch.
Inventory and Road counts are unchanged. See `docs/gold-wave252-hosted-apparmor.md`.
The local BSOD hold remains absolute.

**W249 Unix Context Import client (2026-09-23):** supported Unix/macOS clients
now route status, plan, apply, pause and resume through the daemon's existing
Connector-Control authority. Discovery files are checked and read through one
no-follow nonblocking descriptor; canonical endpoint reconstruction, kernel
peer UID, private endpoint metadata and bounded unambiguous HTTP are enforced.
Independent static review passed, including the descriptor race repair and
accurately documented same-UID ABA limitation. Seven Unix cases join Linux and
macOS native inventories; the real CLI/listener roundtrip includes persistence,
pause/resume and shutdown. Execution remains pending. Inventory: 537 sources,
861 universal native, platform extras Windows 19 / Linux 29 / macOS 28;
98 universal GUI, Group431 / GUI124. CC-04 and Road counts stay unchanged.
W251 is published on `49e58dfb`: Group424 `35805034886` and full CI `35805037288`
are running on that exact milestone. Later source work does not replace its
results or qualify a newer release HEAD. See `docs/gold-wave249-unix-context-client.md`.
No local executable validation was run; the BSOD hold remains active.

**W251 lifecycle fixture correction and W247 evidence (2026-09-23):**
Group424 run `35803121923` on `09ac5d57` executed all 424 cases: **423 passed,
1 failed**, bound to 91 source paths, the matrix, Cargo lock and exact individual
terminals. The failed drain test observed new-lease admission, which returns
`TransitionInProgress` before reaching the account gate. It now observes the
already-issued authority's gate directly; no timeout or production behavior
changes. Fresh Hosted execution is required before calling the repair passed.
Core run `35803119928` passed slim Clippy, test-target typecheck and CLI build;
its SHA-bound reference was imported with the pause/resume commands.
GUI124 run `35803931022` on `3fc79d68` is bound but ran zero builds or fixtures:
the kernel explicitly denied `sys_admin` under AppArmor `unprivileged_userns`
during readiness. A narrowly scoped Hosted runner fix is being prepared.
Inventory remains 537 sources / 861 universal native / 98 universal GUI,
Group424 / GUI124. Road remains 1016 checked / 306 open / 2 partial.
See `docs/gold-wave251-lifecycle-drain-test.md`. The absolute local BSOD hold
remains active; no local executable validation was run.

**W250 precise Hosted namespace diagnostics (2026-09-23):** GUI12435803340455
on ea43839c binds the complete124-case plan and17GUI sources but ran zero
compilations or fixtures: manager/bus readiness passed, then the probe could
not write uid_map. The probe had requested a namespace-root identity that the
real guardian does not use. It now requests the guardian's current UID/GID
mapping, records both maps and checks supported util-linux flags. A failure
remains fatal and captures bounded kernel/AppArmor diagnostics; no host policy,
sysctl, product check or test assertion is weakened. The actual cause beyond
uid_map EPERM and W153/W164 acceptance remain unproven until the next Hosted run.
Counts remain537sources/861native/98GUI,Group424/GUI124; Road unchanged.
See `docs/gold-wave250-hosted-userns.md`. Local BSOD hold remains in force.
**W248 Hosted GUI containment prerequisites (2026-09-23):** source-bound GUI123
on a7f3 executed123 cases:121passed/2failed, with W168 now passing. W153 exposed
an unavailable user manager; W164 exposed a manager-owned unit dead before the
provider launched. The Linux runner now adopts or boundedly starts its regular
systemd user service and standard runtime bus, then checks manager/namespace
capability on the same XDG path used by the supervisor. Failed prerequisites
cannot become a passing readiness receipt. Bounded manager/unit/journal output
is retained for any remaining guardian failure. Actual W153/W164 behavior still
requires GUI124 execution; no product containment check or fixture is relaxed.
Inventory537sources/861native/98GUI and Road1016checked/306open/2partial unchanged.
See `docs/gold-wave248-hosted-gui-containment.md`. Local BSOD hold stays absolute.
**W247 durable Local Import pause/resume (2026-09-23):** authenticated Windows
CLI requests bind both expected revisions and the fixed accountless Local Import
instance. The daemon preserves the selected config path, prepares its exact
source CAS, drains owned import leases with a five-second deadline, then publishes
and installs the matching successor. Prepublication timeout restores admission;
postpublication projection failure remains fail-closed. Responses describe the
reviewed committed successor, not a later possibly concurrent status read.
Six universal regressions and the existing Windows daemon roundtrip cover the
new boundary. Independent source review passed after fixing a response race,
bounded lease drainage and two type-level defects. Hosted execution is pending.
Inventory537sources/861universal native/98GUI; Group424, GUI124. CC-03/CC-04 and
Road1016checked/306open/2partial remain open/unchanged. W246's exact seven-path
Hosted formatting patch was source/SHA/preimage/postimage verified and imported;
no local formatter/compiler/test/runtime was invoked. See
`docs/gold-wave247-context-import-lifecycle.md`.
**W246 bound Recall provenance (2026-09-23):** Main and Buddy now receive passive,
content-free Event, WarmSnapshot or GroundTruth citations from the same verified
recall result. Exact positive source IDs, tier/trust checks, summary sentinel
rejection and both raw/typed transport paths are enforced. Omitted legacy fields
remain decodable; older strict consumers reject cited rows, so paired producer/
consumer deployment is required. No source navigation or content disclosure is
added. Independent static review passed; fresh Hosted behavior remains pending.
Five core identities are selected in addition to the retained25W231 cases, plus
one new GUI reducer case and strengthened existing raw/daemon Main/Buddy cases.
Inventory537sources/855universal native/98GUI; Group418, GUI124; Windows19/Linux22/
macOS21 native extras and26Linux/26macOS GUI extras remain. P2-27 stays open.

Fresh evidence for prior batches: Group41335800840265 on1a6a19d7 passed **413/413**;
all89sourcebindings, matrix, lock and individual execution terminals verified.
Core35800838154 passed test-target typecheck and CLI build/export; its exact-source
SHA-verified reference includes W239 read flags and W242 status. Preflight35801625810
and CodeQuality35801625255 passed on5a52ad92 after the verified one-path W245 format
import. GUI123/a7f3 executed123:121passed/2failed with all17GUI source bindings
and exact terminals verified; W168 passed, W153/W164 exposed missing/failed
systemd user containment. W248 runner repair is separate; W245 Windows remains pending.
Road1016checked/306open/2partial is unchanged. No local executable validation ran.
See `docs/gold-wave246-recall-citations.md` and W239–W245 reports.
**W245 Windows read-root compatibility (2026-09-23):** the descriptor-bound
reader retains ordinary and verbatim UNC roots as well as drive roots, avoiding
an unintended regression for existing allowlisted shares. Device/pipe and relative
namespaces remain refused; component/leaf no-follow checks are unchanged. One
Windows-only path-contract regression is added; live SMB behavior is not claimed.
Inventory537sources/853universal native/97GUI, Windows native extras19 (Linux22,
macOS21), Group413 unchanged. Root also corrects W244's selected source-path count
to the actually verified89. Road1016checked/306open/2partial remains unchanged.
See `docs/gold-wave245-windows-read-roots.md`; actual Windows execution pending.

**W244 Hosted fixture compile repair (2026-09-23):** Group41335800207400 on
a7f3e225 binds all89 selected source paths plus matrix/lock, but compiled no
fixture successfully: two new `McpServers` fixtures omitted `smart_loading`.
Both now explicitly use false, matching the existing default; one redundant
Clap trait import is removed. This is a narrow source repair, not413 passing
cases. Preflight35800382671 passed on18619269 after the exact Hosted-format
import. Inventory537/853/97 and Road1016checked/306open/2partial stay unchanged.
See `docs/gold-wave244-native-fixture-compile.md`. Local BSOD hold unchanged.

**W239–W243 continuation (2026-09-23):** native `fs read` now has an explicit
opt-in codegraph/PreToolUse route with a retained no-follow descriptor, bounded
read and post-read freshness check. Seven universal and three Unix regressions
are selected; the canonical Windows-drive case is required in native Windows CI.
`context import status` exposes the existing authenticated, content-free daemon
status on the current Windows client surface; its parser/route and actual Windows
RPC cases are recorded separately. CRG-05 and CC-04 remain open.

W240 corrects the exact W168 visible rate and uses separate Main/Buddy release
tickets. W153/W164 now distinguish shell entry from envelope-read and retain
bounded launch diagnostics. Their actual child-start cause remains unproven.
GUI123/50fe run35798455505 failed before discovery because `NeothLineEdit` was
not imported; the existing component is now imported. No GUI pass is claimed.
W241 reconciles the two cancellation source guards with the inspected authorized
permit/success-only sample sites. W243 restores all22 real Cluster leaf identities
and keeps20 missing leaf-level GUI contracts explicitly unwired.

Evidence: Core35798450845 on50fe passed slim Clippy, core-test typecheck and public
CLI build/export; exported CLI reference is SHA-bound and unchanged. Group402
35798453231 executed402:399passed/3failed; all85 source hashes, matrix, lock and
actual terminals verified. The failures are the two W241 guards and W243 inventory,
now source-repaired. All four W235 cancellation behavior cases and W238 yearly
settlement passed. Prior GUI116/480 bound all116 executions:113passed/3failed.
Current inventory **537sources/853universal native/97GUI**, native platform extras
Windows18/Linux22/macOS21, GUI123 and macOS custom30 unchanged. Next grouped
selection is **413**, plus two separate BGE cases. Fresh execution remains required;
Road stays **1016checked/306open/2partial**. Local BSOD hold remains absolute.
Reports: `docs/gold-wave239-native-read-enrichment.md`, W240, W241, W242 and W243.

**W233 Buddy TaskDelegate and W235 API repair (2026-09-23):** Buddy now inspects
and mutates exact peer assignments through existing CLI/RPC CAS. Full u64
revisions, bound receipts, busy ownership across A→B→A and truthful committed/
unconfirmed readback are enforced. Three reducer/receipt cases plus four actual
callback fixtures are selected; the macOS native dispatcher/discovery has30cases.
GUI selection becomes **123 = 97 universal + 26 Linux** (also26 macOS extras).
W235's11 Hosted private-interface diagnostics are repaired with the existing
public cancellation observer; the concrete chat close authority stays private.
Source/delta review is complete; Hosted execution remains required. Inventory
535sources/845native/97GUI; Group402 unchanged. Road remains1016checked/306open/
2partial. See `docs/gold-wave233-task-delegate-gui.md` and W235 report. No local
compiler, formatter, parser, test or runtime was executed.

**W237/W238 and W235 compile repair (2026-09-23):** Group39835795048502
executed398 cases on480ff458: **397 passed / 1 failed**. All83 source hashes,
matrix, lock and actual terminals match. The sole yearly-concurrency failure
uses Unix rustix::Errno::EXIST, now recognized before the unchanged bounded,
exact-content readback. W235's Hosted E0277 and unused-mut diagnostics are
repaired without changing cancellation settlement. Recall labels now expose
the actual reduced summary to accessibility in both Chat and Buddy; platform
screen-reader behavior remains unverified. See W235, W237 and W238 reports.
Inventory535/845/94 and Group402 remain. Road stays1016checked/306open/2partial;
these source repairs do not close release requirements. Local BSOD hold remains.

**W235 cancellation settlement (2026-09-23):** explicit authorized cancellation
now awaits the provider terminal WAL acknowledgement across stream opening,
stream consumption and history-compaction utility completion. Concrete-leaf
forwarding is preserved through token-cap, fallback and compactor. Two existing
250 ms chat cases are strengthened; two new real utility/fallback regressions
also bound writer teardown after releasing the authorizer sender. Independent
source review passed; actual Hosted execution remains pending. Selection is
**Grouped402**, inventory **535 sources / 845 native / 94 GUI**, platform GUI
extras unchanged. Preflight35795288640 passed on3e99cfa5; that does not validate
W235. Road remains1016checked/306open/2partial. See
`docs/gold-wave235-cancellation-settlement.md`. Local BSOD hold unchanged.

**W234 GUI fixture/discovery follow-up (2026-09-23):** reviewed fixes preserve
fresh receipts while correcting FIFO-toast expectations, request settlement,
claim-bound citation fixtures and deterministic bounded throughput observation.
W153/W164 child-start remains unresolved; the next Hosted run now records its
precise phase without weakening containment. Grouped394 on1927280f is bound at
384executed/384passed, then one discovery failure left10cases unexecuted.
All79source hashes/matrix/lock/terminals match. Two stale sealed-response module
names are corrected; no tests removed. Exact Hosted updater formatting is
imported. Sources535/native843/GUI94 and Group398 counts remain; Road stays
1016checked/306open/2partial. See `docs/gold-wave234-native-and-gui-recovery.md`.
**W234 native/GUI recovery (2026-09-23):** Grouped340 and341 are admitted at
340/340 and341/341, all71source hashes/matrix/lock/actualterminals verified.
The latter proves W229's real RPC and revoke-first start behavior; Core35792359278
also passed and its generated CLI reference matches exactly. FullCI743 compiled
both native platforms; macOS17600passed/15failed/25skipped. Four reviewed core
repairs address fixture schema, exact AlreadyExists recovery, canonical macOS
paths and read-only cold citation cache. Focused selection becomes398 and
native inventory843 (sources535,GUI94,platform extras unchanged). GUI116 onb1ef
is source-bound105pass/8actualfail/3discoveryfail; the workflow now respects
canonical harness classes and corrected test names. Callback repairs and W235
cancellation remain separate work. Road remains1016checked/306open/2partial.
See `docs/gold-wave234-native-and-gui-recovery.md`. Local BSOD hold unchanged.
**W232 native-suite repairs (2026-09-23):** FullCI35782661515 completed actual
Windows testing at17530passed/3failed/24skipped/1leaky, with no test timeouts.
Three reviewed fixture repairs address watcher-registration timing, module-level
test-only provider scanning and a whitespace-sensitive Buddy callback assertion.
Production behavior and assertions remain enforced. The waiter and GUI callback
are already selected; adding both scanner cases makes **Grouped394**. Actual
post-fix Hosted execution remains required. macOS also compiled successfully
and failed in tests; its diagnostics are under review. Inventory remains
535sources/842native/94GUI with unchanged platform extras, and Road stays
1016checked/306open/2partial. See `docs/gold-wave232-native-suite-repairs.md`.
All executable validation remains on GitHub.
**W231 recall/feedback selections (2026-09-23):** two independent contracts now
share the focused Hosted run:25 existing recall-chip cases and26 existing
response-feedback cases. All51 were absent the actual prior341 selection;
the resulting **Grouped392** union is unique and bound to native identities.
Their separate GUI116 selections contain10 recall and5 feedback cases. P2-27
and P2-28 remain open pending actual execution and literal acceptance. W229's
exact Hosted formatting receipt from35792353017/c20ed504 is imported for2files.
Inventory stays535sources/842native/94GUI with unchanged platform extras. Road
stays1016checked/306open/2partial. See
`docs/gold-wave231-recall-feedback-acceptance.md`. Local BSOD hold remains.
**W229 live cluster delegation assignments (2026-09-23):** the existing
same-user/bearer Audit RPC now commits strict TaskDelegate CAS mutations while
the daemon runs. Setter and final provider admission share a short authority
gate, so revoke-first denies a waiting start before any provider call. Receipts
report their own committed revision; later writers cannot create false commit
failures. Independent source and delta reviews passed. The strengthened real
controller race and authenticated RPC roundtrip require Hosted execution.
Inventory:535sources/**842native**/94GUI, unchanged platform extras; focused
selection **Grouped341**. P2-18 remains open for skill/channel/failover/surface
scope. Road stays1016checked/306open/2partial. See
`docs/gold-wave229-live-cluster-assignments.md`. No local executable validation.
**W230 selection / W226-W227 verified (2026-09-23):** Grouped328
`35790281385` on `aca578a0` is admitted at **328/328**, with all68 source
hashes, matrix, lock and each actual result terminal verified. This confirms
all four W226 fixture repairs and the25 W227 autonomy cases. P2-12 awaits its
GUI cases; Linux GUI116 `35790648880` remains running. W230 selects12 existing
live-throughput cases absent the prior actual execution union, growing the
focused selection to **Grouped340**. Its9 GUI cases are already selected by
GUI116. P2-29 stays open pending actual execution. Inventory remains535sources/
841native/94GUI plus22Linux/22macOS extras and26macOS custom cases. Road remains
1016checked/306open/2partial. W229 live cluster mutation is separate work.
See `docs/gold-wave230-live-throughput-acceptance.md`. FullCI `35782661515`
is preserved; all executable validation remains GitHub-hosted.
**W228 focused Linux GUI acceptance (2026-09-23):** a separate manual,
non-cancelling GitHub lane now binds and executes the canonical **94 universal
plus 22 Linux GUI fixtures**. It prebuilds the real CLI and GUI binary harness,
uses one build job/Xvfb, verifies actual one-test pass terminals, and retains
truthful partial receipts before its bounded job deadline. Independent static
review passed. Hosted results are pending; full native/release CI remains
required. The ongoing Windows/macOS FullCI `35782661515` is preserved.
Inventory: **535 source paths / 841 native / 94 GUI**, unchanged22Linux/22macOS
extras and26macOS custom cases; Grouped328 `35790281385` runs separately.
Road remains1016checked/306open/2partial. See
`docs/gold-wave228-linux-gui-acceptance.md`. No local executable validation ran.
**W226 Hosted repair checkpoint (2026-09-23):** Grouped303 `35788592926` is
source-bound at **299 passed / 4 failed**, all 62 source hashes and exact result
terminals verified. Four fixture setup defects are repaired: mismatched signed
endpoints, a missing explicit assignment, and repeated revision-0 initialization.
The default-deny production rule and assertions are unchanged. Core run
`35788596014` passed slim Clippy, test typecheck and CLI build/export; its exact
source/hash-bound generated CLI reference is imported. The repairs and W227's
25 additional autonomy cases will execute together as Grouped328. Road remains
1016 checked / 306 open / 2 partial; no further checkbox closes. Local executable
validation remains prohibited; see `docs/gold-wave226-verification.md`.
**W227 autonomy acceptance selection / W225 verified (2026-09-22):** corrected
Grouped282 `35787943413` on `5dff0afb` is admitted at **282/282**, with all
58 source hashes, matrix, lock and actual test terminals verified. The real
Claude effect-start role-reload denial case passed. W227 adds 24 existing W138
autonomy cases plus the W145 loop-to-MCP cap case to the actual grouped
selection, growing it to **328** without duplicating native inventory records.
P2-12 remains open until these cases and its separate native GUI cases pass.
W226 Grouped303 `35788592926` remains running; its Core run `35788596014` has
passed slim Clippy and test typecheck and is building/exporting the CLI.
Inventory stays 534 source paths / 841 native / 94 GUI. Road stays
1016 checked / 306 open / 2 partial. See `docs/gold-wave227-autonomy-acceptance.md`.
All executable validation remains GitHub-hosted under the local BSOD hold.
**W226 operator cluster assignments (2026-09-22):** the existing membership DB
now persists exact-key TaskDelegate assignments with default denial and CAS
revisions. CLI show is read-only/no-migrate; set requires the existing offline
authority lock and exact readback. Inbound and executor checks include the final
pre-provider boundary. Independent focused source review passed after fixing
read-only migration and queued/final revocation cases. Seven new behavioral
cases plus fourteen affected existing cases join Grouped303. Hosted behavior
and generated CLI-reference acceptance are pending; P2-18 remains open for
skills/channel/failover and GUI/Buddy scope. Inventory: **534 source paths /
841 native / 94 GUI**, unchanged platform extras and 26 custom macOS cases.
Road remains **1016 checked / 306 open / 2 partial** (1324 total). See
`docs/gold-wave226-verification.md`. W225's first Grouped282 compile errors
were repaired in `5dff0afb`; new run `35787943413` is pending. The synchronized
Road/Progress counters passed Preflight `35788156226` on `02f4c5ea`.
All executable validation remains on GitHub; the local BSOD hold is unchanged.
**W224 accepted / W225 queued (2026-09-22):** P2-10 is now accepted against
`778637e0`: Grouped281 `35785415701` passed all 281 exact selected tests;
58 source-path hashes, the matrix, Cargo.lock and each case's result terminal
match. This covers dependency readiness, typed registry injection, CLI/Channel/
Background/loop/n8n/Cron/Sub-Agent retention, reload and subject/policy isolation.
Independent contract review passed. Road: **1016 checked / 306 open / 2 partial**
(1324 total). See `docs/gold-wave224-registry-acceptance.md`.
W221 consent-denial cases both passed in the same run. W225 adds the real
Claude effect-start role-reload denial regression; independent source review
passed, Hosted execution is pending. Its separate warm-pane fence remains open.
Inventory: 532 source paths / 820 native / 94 GUI, unchanged platform extras;
Grouped282 includes W225. Slim-core Clippy and test typecheck on `c4203898`
passed; CLI export is still running. Full CI `35782661515` remains running
on `74334d4b` for Windows/macOS. Local executable hold remains absolute.
**Hosted checkpoint (2026-09-22):** Grouped275 `35784185143` on `e716997a`
passed 275/275 exact cases, including actual CLI fallback; 57 source paths,
matrix, lock and per-case terminals are verified. Grouped281 `35785415701`
runs W221 and the four additional W224 acceptance cases. W223's focused
slim recheck `35784699877` exposed one E0282 after cfg(test) gating;
explicit `None::<&str>` now preserves inference and is queued for recheck.
W221's exact Hosted formatter receipt is imported. No new Road closure.
**W221 retry consent-denial receipt + W224 acceptance selection (2026-09-22):**
an already admitted retry stopped by the final live-consent fence now emits a
bounded `authorization_denied` terminal. Per-attempt error classes remain exact;
the denial retains the chain's origin class. Core and GUI require attempt >=2,
non-Auth and no observed follow-up. The mixed-chain fixture uses the actual
authenticated home WAL and Buddy reader. Independent source review passed;
Hosted behavior is pending. Role/effect-start denial visibility remains open.
W224 selects four existing Channel/Block-D tests absent from earlier grouped
runs; Grouped281 now includes them and the two W221 cases. P2-10 remains open
until exact selected results pass. Inventory: 532 sources / 819 native / 94 GUI,
unchanged 22/22 platform GUI extras and 26 custom macOS cases.
**Confirmed:** Grouped274 `35783436951` on `e8772e77` is admitted at274/274,
including both W220 tests, with all57 source hashes/matrix/lock/terminals bound.
See `docs/gold-wave221-verification.md` and `docs/gold-wave224-registry-acceptance.md`.
Road remains1015 checked/307 open/2 partial. Local BSOD hold remains absolute.
**W223 slim-core Clippy corrections (2026-09-22):** the Linux quality job
`106931734757` in full CI `35782661515` reported nine diagnostics. Four source
files now use test-only gates for genuinely test-only wrappers, direct function
references and an expression return; no lint level is relaxed. Fresh Hosted
Clippy remains required. Windows/macOS native jobs continue on `74334d4b`.
**Confirmed regression result:** Grouped272 `35782455869` on `35c410a8` is
admitted at **272/272**, including the actual aggregate Skill rollback fix.
All 56 source hashes, matrix, lock and individual result terminals match.
W220/W222 run separately in Grouped274/275; W221 remains active. Inventory is
532 sources / 817 native / 94 GUI plus existing platform selections; Road
counts remain unchanged. See `docs/gold-wave223-verification.md`.
**W222 direct CLI fallback registry coverage (2026-09-22):** a real
`run_chat_with` regression records the primary request, publishes signed Skill
and accepted config B, then takes the actual typed-quota fallback. Both reached
provider leaves must receive equal prompt/system bundles with the exact admitted
A registry, while the newly loaded registry contains B. It uses in-process
providers and does not claim network delivery. Independent source review passed;
Hosted execution is pending. Inventory: 532 sources / 817 native / 94 GUI,
Grouped275. W221 retry denial receipts are still in progress. Full CI
`35782661515` continues on `74334d4b`; nine Linux slim-Clippy diagnostics are
being repaired without cancelling other platform jobs. Road unchanged; see
`docs/gold-wave222-verification.md`. All executable validation remains Hosted.
**W220 persisted background registry coverage (2026-09-22):** real installed
Skill/authority publication A-to-B now has a fixture across metadata rendering,
required Block D, signed durable job storage, bounded private read, approval
verification and the worker's unchanged-config gate. The loaded request must
retain the exact A envelope while the live registry contains B. A separate
accepted-config-B case requires the existing pre-dispatch gate to refuse the
queued A job. Independent source review passed; Hosted execution is pending.
This is persisted-request and pre-dispatch coverage, not full detached CLI
process acceptance. Inventory: 532 sources / 816 native / 94 GUI, Grouped274;
GUI platform counts remain 22/22 and macOS custom count 26. Full CI
`35782661515` continues on W219 source `74334d4b` and must not be cancelled.
Preflight `35782660911` passed for that source. Road counts remain unchanged;
see `docs/gold-wave220-verification.md`. The absolute local BSOD hold remains.
**W219 Buddy retry status compatibility (2026-09-22):** the strict GUI DTO now
accepts W217's versioned provider retry history. Missing history defaults to
unavailable; malformed present blocks reject the status. Only six bounded
content-free fields reach the passive card, with explicit incomplete/stale
history labels and no delivery claim. The real refresh fixture covers safe
publication and preservation of the previous projection after invalid output.
Inventory: 531 sources / 814 universal native / 94 GUI, plus 22 Linux and
22 macOS GUI extras; macOS custom harness has 26 cases. Hosted GUI compilation,
callbacks and visual/accessibility acceptance remain open.
**Hosted checkpoint:** Core/CLI `35778911671` on `28cdd082` passed.
Grouped270 `35778908791` is source-bound at 269/270, including all four W217
cases, W198 n8n 6/6 and W199 Cron 5/5. Its only failure still retains installed
`alpha` in the aggregate-overflow fixture; the new exact-baseline assertion
shows a production rollback bug. The aggregate error branch now rebuilds a
fresh trusted bundled-only map; review passed, Hosted behavior is pending.
Grouped272 `35779348058` independently confirms 271/272 before this fix.
No Road checkbox closes on this checkpoint; 1015 checked / 307 open / 2 partial
remain. Local compilation, tests, parsers and GUI execution remain prohibited.
See `docs/gold-wave219-verification.md`.
**W218 Buddy embedding GUI bridge (2026-09-22):** Buddy Config now exposes
confirmed embedding selection and BGE Verify/Pull/Repair/Prune through the
existing `buddy embedding --config PATH` lifecycle. Resources and Buddy share
one mutation singleflight and publication revision; both consume the strict
existing DTO, selected-model readback and fresh-probe verifier. Qwen lifecycle
controls remain unavailable. Independent source review passed, including a real
native MainWindow callback fixture with the staged CLI, exact instance path,
cross-surface duplicate rejection, malformed/mismatched output and stale/fresh
probe cases. Main GUI embedding parity entries are corrected to their already
existing W211 wiring; standalone list remains Unwired and status Partial.
Inventory is 531 sources / 814 universal native / 93 GUI, plus 21 Linux and
21 macOS GUI extras; macOS custom harness has 25 cases. Grouped272 adds two
parity-contract cases. Hosted GUI compile, callbacks, visual/accessibility and
full native acceptance remain open. Road counts unchanged; see
`docs/gold-wave218-verification.md`. The local BSOD hold remains in force.
**W217 Hosted compile correction (2026-09-22):** Grouped270 `35778050758`
on `33566416` stopped before tests with seven E0433 diagnostics: new nested
fixture references used the wrong module depth. They now use the explicit
`crate::providers::claude_retry` path; production behavior is unchanged.
Superseded Core `35778054554` and Grouped `35778613062` are confirmed cancelled.
The W216 baseline correction and exact W217 formatting are published at
`fdbea060`. Fresh Hosted compilation and all 270 cases remain required.
**Hosted regression checkpoint (2026-09-22, W216/W217):** Grouped266
`35776784587` on `558163ad` is source-bound at 265/266. All W215 tests and
nine of the ten added W216 cases passed; the only failure was the overflow
fixture's static bundled count (198 versus 197). The fixture now compares the
exact ordered no-installed-skill baseline under the same readiness probe and
still requires complete removal of partially admitted installed candidates.
Core/CLI `35776787510` passed. W217 is published at `33566416`; its exact
source/SHA-bound formatter receipt `35778052636` is imported. Fresh Grouped270,
full native CI and GUI evidence remain required; Road counts are unchanged.
**W217 durable retry visibility (2026-09-22):** classified Claude retry stops
now carry versioned, content-free receipts in the existing provider terminal.
Freshly authorized successor intents retain an explicit chain and 1-based
attempt. Buddy status reads bounded authenticated WAL history and accepts a
follow-up only in the same session with the immediately succeeding attempt;
this is lifecycle evidence, not proof of a transport send. Auth and exhausted
stops remain final. Independent source review passed, including actual permit
terminal pairing and authenticated readback tests. Four selected regressions
bring Grouped to 270 and inventory to 531 sources / 813 universal native / 92
GUI. Fresh Hosted execution remains required. W216 is published at `558163ad`,
with exact Hosted formatting in `4273f118` and passing Preflight `35777121108`.
Old full CI `35765595152` is complete: macOS reached its 100-minute compile
limit while paging, without a Rust diagnostic; its 1.31 GiB partial cache was
saved. Fresh consolidated native validation remains required. Road counts are
unchanged. See `docs/gold-wave217-verification.md`; local BSOD hold still applies.
**W216 Windows regression repair (2026-09-22):** the 14 failures from full CI
`35765595152` are repaired in source. A real local-model refresh bug erased
an interrupted operation's uncertainty; refresh now reapplies its exact durable
receipt. The remaining fixes align admission fixtures, canonical origin/sender
metadata, read-only long-poll timing, guarded Cron registry, CLI/GUI parity and
source gates with their current contracts. Four obsolete refusal-retry tests
now verify W206's intended terminal mirror, preserving selected/fresh registry
isolation, decoded audit ordering and final visible-response hash/byte binding.
The older retry/local-shadow path is unreachable under that terminal contract;
this does not prove broader P2-10 recovery coverage. W215's disabled-skill fixture
now authorizes before operator-policy disable. Grouped255 `35774216773` on
`71c0436a` is source-bound at 253/255: both runtime propagation tests and the
actual-start role fence passed; scanner and admission fixtures are repaired.
Core/CLI on that source and Preflight on `eefe379d` passed. W216 adds ten exact
cases to the grouped lane (266); inventory is 530 sources / 809 universal native /
92 GUI. Fresh Hosted behavior is required. The old macOS full-CI compile remains
in progress. Road counts remain 1324 / 1015 checked / 307 open / 2 partial.
See `docs/gold-wave216-verification.md`; the local BSOD hold remains absolute.
**Hosted regression checkpoint (2026-09-22):** Grouped251 `35772612247` on
`7689717b` is source-bound at 250/251; all 12 W213 and three W214 tests passed.
The only failure was an external test file counted as production by the raw-call
scanner. Explicit file-wide cfg(test) recognition and a regression correct its
scope without widening production allowlisting. The W215 standalone QA API now
delegates to one shared implementation, preserving two production call sites.
The current lane is Grouped256 / 530 sources / 803 universal native / 92 GUI.
Old full CI `35765595152` Windows completed 17,489 cases with 14 failures;
those are under bounded subsystem repair while macOS continues compiling.
No Road checkbox or release gate closes from these results.

**W215 sub-agent registry / actual-start role fence (2026-09-22):** the real
CLI fan-out now captures one admitted Skill registry from its exact accepted
config and instance home, requires it in the production worker, and preserves
the same guarded envelope through primary/QA/retry requests. Final primary
and QA system limits are checked before the first provider call. Three new
regressions and independent source review cover admission and propagation.
The W213 correction also rechecks first/retry tmux sends after readiness and
shares the role decision with the actual effect-start authority before
AllowOnce is spent; one new race regression and source review cover that gap.
Inventory is 530 sources / 802 universal native / 92 GUI identities; Grouped255
awaits Hosted execution. Core/CLI `35772615830` passed on prior `7689717b`,
and its source/SHA-bound Buddy command reference is imported. Road counts
remain unchanged; see `docs/gold-wave215-verification.md`.

**W213/W214 Hosted compile repair (2026-09-22):** Grouped248 `35771699017`
on `889d3df8` stopped before test execution with three E0061 diagnostics in
existing Copilot token fixtures. Their transport-only permit constructors now
supply explicit `None` for the added role decision. All constructor call sites
were textually checked; post-fix Hosted compile/behavior remains required.
W214 is published at `36802b32`, with exact Hosted formatting in `3184126e`.
W212 remains admitted at 236/236. Road counts and the local BSOD hold are unchanged.

**W214 Buddy embedding parity (2026-09-22):** `neoth buddy embedding --config
PATH list|status|select|probe|pull|repair|prune` now delegates to the existing
typed model lifecycle, retaining exact instance scope, updater/audit policy,
probe freshness and prune safeguards. Independent bounded source review passed;
three new regressions bring Grouped to 251 and inventory to 529 source paths /
798 universal native / 92 GUI identities. Hosted behavior and the generated CLI
reference update are pending. W213 is published at `889d3df8`; Grouped248
`35771699017` and Core/CLI `35771703379` are running, and its source/SHA-bound
Hosted formatting receipt `35771681385` is imported with this batch. Road
counts remain unchanged; see `docs/gold-wave214-verification.md`.

**W213 Council role admission (2026-09-22):** optional closed provider/model
rules now bind primary and recursive Council leaves. The retained policy
identity reaches lifecycle audit and final complete/stream/event transport
checks, including Claude internal retries. Daemon role-policy reload revokes
older attempts without changing their topology/budget/channel authority; CLI
commands retain fixed snapshots. Independent source review passed. Twelve new
regressions bring the grouped lane to 248 and inventory to 529 source paths /
795 universal native / 92 GUI identities, with platform extras unchanged.
Hosted compile, behavior and full-CI results are pending. Normal dispatch,
fallback, background/sub-agents and GUI controls remain P2-15 follow-ups.
No Road box closes; see `docs/gold-wave213-verification.md`.

**W212 Hosted acceptance (2026-09-22):** Grouped236 `35769179702` on
`0d501bad` passed all 236 actual tests after the four fixture corrections.
All 47 source paths, exact test identities, matrix and Cargo.lock match the
run commit. This includes all 17 new generation tests and all 14 existing
index/forget regressions. Core test-target type-check and CLI build already
passed on `02a10972`; fresh full-CI/GUI/release acceptance remains open.
W213 Council role policy is in final implementation and independent review,
including role-only reload revocation and the real Claude internal retry fence.
Road remains 1324 total / 1015 checked / 307 open / 2 partial. Local BSOD hold
continues; all executable validation runs on GitHub-hosted runners.

**W212 Hosted behavior and regression repair (2026-09-22):** Grouped236
`35767413693` on `02a10972` executed all 236 selected cases: 232 passed and
four failed; all 17 new generation tests passed. Source hashes for 47 paths,
exact identities, matrix and lock are admitted. Three older index fixtures
still assumed unscoped snapshots: they now prove media-scope-preserving forget
and SQLite fallback for a broader snapshot versus a kind-filtered query. The
v42-to-v43 reopen regression now expects the current schema after normal open,
while retaining its explicit 42-to-43 migration and preservation assertions.
The corrective sources need a fresh Hosted run. Core/CLI `35767417912` passed
and the generated reference matches the checked-in file. W213 stays uncommitted.

**W212 published / Hosted checkpoint (2026-09-22):** generation isolation is
on main at `104343bf`, followed by the narrow c417 Clippy source repairs in
`02a10972`. Source/SHA-bound Hosted formatting is imported in `9ea97d56`;
its Preflight `35767604603` passed. Core test-target type-check and public CLI
build `35767417912` passed; the source/SHA-bound CLI reference is unchanged.
Grouped236 `35767413693`
is running on `02a10972`; behavior and fresh full-CI acceptance remain pending.
W213 is now implementing primary/recursive Council role admission. Source
tracing confirmed that ordinary-chat fallback is a separate consumer, so no
new Council fallback selection is introduced or claimed covered. Road counts
and the workstation BSOD hold remain unchanged.

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
