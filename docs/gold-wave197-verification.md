# W197: bounded Skill prerequisite admission

The authorized loader now holds private pending candidates until prerequisite
admission completes. It resolves policy and installed same-ID authority first,
then checks the closed Drawio/PPT/Graphify/eleven-OfficeCLI family map before
calling the existing RuntimeSkill constructors. Unready candidates are omitted;
an unready installed replacement cannot expose its bundled predecessor.

One immutable readiness result covers the effective and policy-effective bundled
fallback candidates for a build. Each enabled prerequisite family is checked
once, sequentially. Disabled families do not spawn probes. A later build obtains
fresh readiness; retained earlier snapshots keep their original bodies.
The accepted config epoch is checked after async work, and the registry retains
its existing authority-bound publication fence.

Python and OfficeCLI probes use fixed argv and null streams, a five-second wait,
kill-on-drop, and a bounded 250-ms termination wait. Graphify delegates to the
existing contained GraphifyRuntime discovery. Drawio still requires W192's
verified materialized siblings; optional Graphviz autolayout is not a global
Drawio admission requirement. No manifest, hash, authority-record or public
RuntimeSkill constructor contract changed.

Eight new deterministic fixtures cover exact IDs, disabled/no-probe behavior,
one OfficeCLI probe, NotReady filtering, force-enable, bundled fallback,
authority-admitted installed override, and unchanged Ready provenance. The
installed fixture first proves Ready installed admission, then changes only
readiness at the same config epoch and checks exclusion plus retained old body.
The grouped lane additionally selects the existing real concurrent registry
reload test and exact-metadata/snapshot-pinning resolver tests.

Independent static review passed after bounding timeout cleanup, eliminating a
second fallback probe, and propagating both blocking-worker result layers.
Hosted formatting, compilation and behavior remain pending. No local compiler,
formatter, parser, fixture, product or runtime command ran under the BSOD hold.
This slice does not close P2-10 or prove external tool execution after admission.
