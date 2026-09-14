# W48, W49 and W51 codegraph consumer and Doctor verification

## Scope and final-evidence boundary

This verification record covers the W48/W49 codegraph consumer
and W51 Doctor batch. The admitted publication scope is **12 changed source
files and 19 publication paths**; the expected retained final source union is
**252 inputs**. NativeTestBuild04 passed from 251 source inputs in 4m16s,
with 206.31 GiB minimum free memory and 10.85 GiB peak build working set.
Selected runtime04 passed 2,119 tests with no failures or ignored tests in
124.30s, selected exactly from the fresh 14,649-test catalog. Strict native
Clippy, all four contract targets, Python integrity checks, the CI matrix and
the separate generated CLI-reference test also passed.

The build-input manifest is explicitly **derived admission evidence**, not a
fresh snapshot captured at Build04 or Clippy03. The capture helper printed
JSON that was not saved, leaving two stale manifest copies. Those copies are
retained unchanged. An independent review confirmed that the preserved
251-input Build03 inventory differs only at `coding/dispatcher.rs`; its new
SHA-256 was recorded before Build04. The replacement manifest combines that
single admission with the unchanged prior hashes and matches all 251 current
inputs. It carries a current derivation timestamp and the retained inputs;
the post-repair byte count comes from the matching current file. The separately
saved post-docgen capture contains all 252 current inputs.

No additional roadmap checkbox closes. Counts remain **1324/1014/308/2**;
CRG-04, CRG-05, and their parents remain open.

## Operator-facing read surfaces

`neoth code-map diff-test-gaps --root PATH` binds one analysis to an explicit
repository root. It accepts exactly one source: working tree by default,
`--staged`, paired `--base REF --target REF`, or `--stdin`. Direction, depth,
node count, and stale handling are bounded. The corresponding read-only MCP
tool is `codegraph_diff_test_gaps`: `root` is required, `source` is
`working_tree`, `staged`, `committed`, or `stdin`, fields must match that
source, unknown fields are rejected, and the UTF-8 diff-byte cap applies before
parsing.

The CLI and MCP routes return typed, generation-bound observed-test evidence
for that exact impact. Empty observation is uncertainty, never proof that a
test does not exist. Raw unified diff, source text, and test bodies do not
enter the MCP response, stored citation, or provider projection. The nested
coding receipt retains the root identity, index/graph generations, impact
digest, and typed outcome; its bounded projection is the provider-visible form.

Before a service-owned apply dispatch, the explicit physical repository root
and code-map database bind a read-only, bounded advisory. Missing, stale, or
unavailable evidence is a typed advisory outcome. It does not authorize apply
and does not create, refresh, migrate, rebuild, or repair a database.

Doctor observes structural code-map readiness through a root-scoped read-only
query. Missing, corrupt, and stale stores report lifecycle-owned,
not-assessed state. Doctor does not make executed-coverage or test-absence
claims and does not migrate, refresh, rebuild, or repair evidence.

## Persistence and fixture boundaries

A valid SQLite read-only WAL reader may create its normal coordination sidecars.
The fresh/stale Doctor fixtures therefore retain the main database bytes,
serialized map, index/graph generations, and freshness result, permitting only
`code_map.db-shm` and an empty `code_map.db-wal`; a nonempty WAL or any unknown
code-map artifact fails the fixture. Absent and corrupt paths retain stricter
exact artifact equality and stay sidecar-free.

Existing trusted built-in MCP registrations with the exact previous nine-tool
allowlist migrate to the ten-tool list, including `codegraph_diff_test_gaps`.
Repeating migration is idempotent. Unknown, duplicate, customized, or differently
bound registrations retain the existing strict checks.

The previously published schema v9→v10 migration adds nullable exact target-file
identity; legacy null targets remain non-exact. Doctor's read-only path does not
run this migration.

The final capped-impact fixture repairs only its synthetic unified diff. Its
three-line target has a hunk wholly inside the parser-certified declaration,
so it produces an exact symbol seed and exercises the typed cap with
`max_nodes=1`. Root validation confirmed Git accepts the contextual LF patch,
the raw-patch sentinel is retained in the fixture assertion, and the same
contextual shape is accepted against a CRLF checkout. No production apply,
authorization, WAL, impact, or cleanup behavior changed for that repair.

## Historical local diagnosis retained

| Attempt | Result | Retained meaning |
| :-- | :-- | :-- |
| Selected runtime01 | 2107 passed / 9 failed | Historical failed run; not pass evidence. |
| Selected runtime02 | 2115 passed / 3 failed | Historical failed run; narrowed runtime fixture defects. |
| Selected runtime03 | 2118 passed / 1 failed | Historical failed run; led to the capped-hunk repair. |
| Capped-impact repair04 | Root fixture validation confirmed | Precise-symbol contextual hunk, LF/CRLF Git acceptance, and sentinel coverage; this is not Build04 completion. |

The stale-digest repair preserves the intended distinction: a fresh impact and
the same `--allow-stale` request after an on-disk change have the same root and
generations but different canonical digests because `stale` is serialized into
the result. Repeating that unchanged stale request produces the same stale
digest, while its typed rejection does not query coverage.

## Review and CI context

The reviewed work inputs retain W48/49 composed-04 (**APPROVE**) for the CLI,
MCP, nested receipt, and pre-apply advisory surfaces, plus W51 repair-02
(**APPROVE**) for Doctor lifecycle-readiness observation. The final batch
extends those retained behaviors to the 12-file admitted scope without changing
their boundaries.

Security on `ed2a` succeeded on attempt 2 after 23 individually reviewed
alerts. The earlier Linux 16284/1 and Windows 16217/1 outcomes share the
reviewed cost-fingerprint cause; its repair is admitted. macOS remains pending.
Those facts do not establish cross-platform acceptance or release readiness.

## Root-owned final-publication evidence

| Required evidence | Final status |
| :-- | :-- |
| NativeTestBuild04; 251 frozen build inputs | PASS, 4m16s; min206.31 GiB / peak10.85 GiB |
| NativeProviderClippy03 | PASS, 5m26s; min205.93 GiB / peak11.26 GiB |
| Selected runtime04 | PASS, 2119/0/0 in124.30s; exact catalog projection |
| Four contract targets | PASS, 15/0/0; 5m19s build, min205.76 GiB / peak11.09 GiB |
| Generated CLI reference | PASS, separate docgen test; generated artifact retained |
| Python integrity and CI matrix | PASS, 19 lost-feature +11 roadmap +8 release +7 CI-cadence tests; matrix assertions pass |
| Final source manifest and test matrix | 252 current inputs, exact2119-test projection and five executable hashes verified |
| Source-input custody | Independently reviewed admission-derived251-input manifest; original stale copies retained |
| Linux/Windows repair revalidation and macOS result | **PENDING** |
| Commit and push | Local checks complete; exact19-path index and direct-main publication recorded separately |
| Exact-head CI and release | Outstanding; the prior-head CI results above do not close these gates |
| Roadmap disposition | No new closure; counts1324/1014/308/2 |

W50 and W52 remain outside this batch and receive no feature, validation, or
progress assertion here.
