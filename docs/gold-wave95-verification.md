# W95-W103 - configured MCP local reads and observed runtime repairs

W102 adds a real direct-CLI regression for an explicitly selected external
ReadPath tool. Per-server allowlist denial, required confirmation and a
configured PreToolUse block each retain their typed error and prevent entry to
the injected child-start closure. The fixture checks the durable request-bound
trust outcome: static gates record `Denied`; the existing authorization-before-
hook order records `Allowed` before the hook blocks execution. It does not claim
that an authorization audit means a tool ran. Disabled-server selection remains
upstream and direct-CLI cancellation remains intentionally unbound; neither is
claimed by this fixture.

[Full CI 35113128375](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35113128375)
on `5e353a168db45234383cfbf735c7835a9ef17300` progressed beyond the W101 argument
errors. Strict Linux lint then found three wrappers used only by tests. W103
limits exactly those wrappers to `cfg(test)` while production keeps its trusted-
descriptor entry points. The failed Linux job also uploaded a restored older
JUnit file although Nextest never ran. The workflow now discards that file
immediately after restoring its Cargo cache, before any format/lint failure can
reach the always-run upload. The old uploaded report is not accepted as evidence.
These source corrections require fresh GitHub validation; other running platform
and preview jobs retain their value for the earlier source only.

The latest full compiler run exposed two missing production call arguments.
[CI 35111462773](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35111462773)
on `ac281eb6251940c8b2a871c8e5d69e793585d162` reports E0061/E0308 in
`loop_engine/engine.rs` and `cli/serve_pipeline.rs`. W101 supplies the configured
selector list from each caller's existing accepted configuration, in the same
position used by the chat path. This introduces no reload or default-empty
workaround and preserves the W96 identity fixtures. Bounded source inspection
also covered all current dispatch-loop and tool-loop callers.

That source had passed [Preflight 35111313338](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35111313338)
and [Code Quality 35111313695](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35111313695);
those lightweight checks do not compile the workspace. The invalid-source full
CI and [preview 35111467760](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35111467760)
were cancelled after the shared compile blocker was established. Neither is
runtime or portable-artifact acceptance. The repaired source requires fresh
GitHub-hosted compilation, strict lint, 58 native and 7 GUI test identities,
and actual portable acceptance. All local validation remains suspended.

W95 extends the existing bounded code-map sidecar to explicitly configured MCP
local path reads. `code_map.outline_enrichment` remains false by default and
`enrichment_selectors` defaults to an empty list. Each selector names one exact
server ID and tool, the `ReadPath` kind, and the fixed `path` argument. Validation
bounds the list and identifiers and rejects duplicate pairs. The existing W53
built-in outline route retains its master-switch-only behavior.

Chat/provider dispatch and direct MCP CLI calls carry the accepted code-map
configuration. They take the selected server and the trusted generated
`neoth-codegraph` descriptor from the same already-loaded `McpServers` snapshot.
The planner neither reloads a raw registry nor guesses a database from the home
directory. The selected server still controls authorization and the actual
bound tool call; selection grants no permission and performs no remote-path
translation.

The shared read-only planner retains canonical root and generation binding,
freshness checks before and after the actual call, bounded context, untrusted
framing and W79 duplicate suppression. Missing or inapplicable enrichment leaves
the ordinary tool result and its existing gate semantics intact. Config reload,
Doctor diagnostics and the configuration reference describe the new selector.

Independent source review approved the admitted candidate and the separate
Doctor correction. Master-enabled built-in outline readiness still works with
empty selectors; Doctor assesses the generated descriptor and physical index
before reporting readiness, and describes additional configured selectors
separately. Dedicated real-call fixtures cover the configured direct-CLI and
provider-dispatch crossings. The source manifest and test matrix below retain
their exact identities and hashes; their execution is pending remote CI.

W96 repairs the concrete failures observed in the completed Windows/macOS run:

- The channel retry/fallback fixtures now resolve their operator through the
  existing identity-v2 store. An untrusted raw inbound UUID never grants recovery
  authority. Production admission and strict successful-recovery assertions stay.
- W53 again tests the built-in route without a precomputed hook from a different
  admission. W79 retains distinct sidecars and exact duplicate suppression,
  including a regression that different call IDs must remain distinct.
- The shared GUI provider fixture requires both prepared context sources and
  checks every source against persisted root/generation provenance. W73 examines
  decoded provider context instead of comparing a raw Windows path to escaped
  outer JSON. No new provider protocol field is added.
- The Buddy impact panel compares the lifecycle root digest to the same
  domain-separated digest of the impact root, using the existing shared helper.
  The former digest-versus-raw comparison discarded valid results. Canonical
  root matching remains, and a focused regression rejects a different physical
  root.
- The macOS main-thread test entry accepts the exact Nextest invocation
  `--exact <fixture> --nocapture` as well as its existing equivalent ordering.
  Unknown arguments and fixture names still fail; ordinary platform registration,
  non-macOS no-fallthrough and the W93 lint correction remain.

No local formatter, parser, test, compiler or product runtime was executed.
The [source manifest](verification/gold-wave95-96-source-manifest.json) and
[test matrix](verification/gold-wave95-96-test-matrix.json) distinguish reviewed
source from pending execution. W97 now rejects unknown selector fields and adds
exact list/byte-bound fixtures. Its real selected-call matrix covers master-off,
empty selectors, pair mismatch and invalid arguments without a sidecar. A real
selected child also changes the indexed source before replying: the parent
requires the ordinary result, exactly one call and no sidecar after the shared
post-call freshness check. Independent review approved these additions.

Preflight [35108731972](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35108731972)
on the first W95/W96 publication failed at Rustfmt. W98 applies only the layouts
printed by that remote formatter; it was not run locally. The updated matrix
also corrects the Doctor fixture's actual module identity, `omi_tests`. Fresh
remote formatting, static contracts, strict lint and runtime proof remain pending.

The next [Preflight 35110334725](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35110334725)
reported formatting in the newly added W97 fixture bodies. W99 applies those
printed layouts. Source inspection also corrected ownership of the child's
root across loop iterations and replaced its constant counter-file value with
an incremented count of actual calls; the parent still requires exactly one.
These fixture changes do not alter production behavior or weaken the freshness
assertion. Remote execution remains required.
Preflight [35111056985](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35111056985)
then requested only a final line wrap for the counter write; that exact remote
formatting output is applied with no further behavioral change.

The preceding W93 source `4141894037d092e128286bd386e664e12e8a22ed` passed
[Preflight 35100677231](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35100677231)
and [Code Quality 35100676058](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35100676058).
Its [preview 35100765685](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35100765685)
passed the actual empty-input receipt/hash checks, compiled the CLI in 33m18s
and migration/relay binaries in 20s. GUI compilation then reached its 45-minute
step deadline without an artifact. The run saved a newer compatible interrupted
cache; no compiler error or OOM cause was established. That source is distinct
from the current candidate, and portable acceptance has not run yet.

The measured W99 recovery raises the next current-source GUI bound from 45 to
60 minutes and the outer job from 315 to 330. Explicit bounded phases now total
302 minutes, retaining the same 28-minute reserve. One Cargo worker, Rust 1.93,
static CRT, locked package-specific commands, preview profile, cache compatibility
and all portable-helper limits remain. The prior run spent about 21m28s in the
GUI feature's core compile, leaving only about eleven minutes after the final
dependency messages. The additional fifteen minutes is a bounded recovery
allowance, not evidence of a completed or predicted build duration.

The completed [full CI 35097577183](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35097577183)
failed on `cc387be72092dc62da1b1965e0a3bf6634b9567c`.
Windows compilation completed in 44m08s; its 26m37s Nextest run completed with
16,735 passing tests (one leaky), seven failures and 22 skipped tests. Failures
cover two channel retry/fallback fixtures, W53 sidecar provenance, both copies
of the GUI provider-controller fixture and two Buddy callback fixtures. Their
completed job log is the input for focused W96 repairs; no passing result is
inferred for them. macOS compiled in 76m39s and passed native GUI fixture discovery;
its 11m17s Nextest run reported 16,789 passing tests, ten failures and 23 skips.
Five failures were rejected harness invocations before their GUI bodies ran;
the other failures belong to the shared channel, W53 and GUI-controller groups.
Linux stopped at the strict harness diagnostics fixed by W93. Eleven other jobs
passed. None of these older results supplies exact-source acceptance for this
new candidate.

All new formatting, contracts, lint, compilation and runtime gates run on
GitHub-hosted runners. Native Read/Grep/Glob/Bash provider execution, broader
GUI/Buddy controls, installed/visual/provider-live and release acceptance remain
separate open requirements. No CRG checkbox closes from this implementation or
source review: **1324 total / 1015 checked / 307 open / 2 partial**, raw309 /
pre-tag308.
