# W95-W96 - configured MCP local reads and observed runtime repairs

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
source from pending execution. W97 separately addresses remaining dedicated
configured-selector negative-call and configuration-bound fixtures; those are
not counted as implemented or passed in this batch.

The preceding W93 source `4141894037d092e128286bd386e664e12e8a22ed` passed
[Preflight 35100677231](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35100677231)
and [Code Quality 35100676058](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35100676058).
Its [preview 35100765685](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35100765685)
passed the actual empty-input receipt/hash checks, compiled the CLI in 33m18s
and migration/relay binaries in 20s, then entered GUI compilation. That source
and any resulting artifact are distinct from the W95 candidate.

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
