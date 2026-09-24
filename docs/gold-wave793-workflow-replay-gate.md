# W793 — manual workflow-replay release witness gate

`packaging/workflow_replay_gate.py` validates the machine report emitted by
`neoth eval run`. It does not run `neoth`, construct a provider, contact a
provider, or create any operator cost. It accepts only an explicit pair of
operator-supplied artifact paths and requires their exact corpus/report
relationship at the tagged source revision.

The consumer checks schema 1, exact corpus bytes, the candidate Git revision,
the fixed `contains-v1` scorer, all and only the corpus episode IDs, every
episode `pass`, true top-level `passed`, valid config/reply/selected-skill
digests, and the actual containment statement. The only allowed real-home
effect is `provider_consent_and_cost_usage_audit`; external tools are
`deny_all`. It therefore neither invents an observed-zero side-effect metric
nor accepts an unbound canned report.

Run the local gate after a deliberately initiated replay with
`--corpus`, `--report`, `--expected-source-revision`, and
`--emit-manifest <path>`. It first validates the raw local inputs, then writes
only a content-free witness: corpus SHA-256, a hash of the exact episode-ID
set, source SHA, count, scorer, projected config fingerprint, effective
secret-free public-config SHA-256, containment and pass state.
The corpus, prompt, expectation, reply, provider/model labels, skill IDs and
raw report remain solely on the operator's machine.

`Manual workflow replay witness` is a `workflow_dispatch` workflow that accepts
only that content-free manifest, validates it on `main`, and retains it as an
Actions artifact named `workflow-replay-witness-<source-sha>`. This artifact is
not treated as private storage; its format deliberately has no workload text.

The release workflow is opt-in: set the numeric Actions variable
`NEOTH_WORKFLOW_REPLAY_RUN_ID` to one successful witness workflow run for the
exact candidate source. The release downloads exactly one unexpired,
same-source witness artifact from that run and validates it before packaging.
An absent variable keeps the standard release cost-free; an invalid, stale,
wrong-workflow, failed, mismatched, or malformed run/artifact fails closed.
Neither workload prompts nor replay reports are committed to the repository or
uploaded to Actions. The public manifest carries only a well-formed claimed
result; it cannot establish how that manifest was created
or independently reproduce the retained local corpus/report bytes.

This is a release consumer for an operator's intentional live-replay evidence.
It does not prove provider quality beyond the contained `contains-v1` episodes,
and it does not make a provider call automatically.
