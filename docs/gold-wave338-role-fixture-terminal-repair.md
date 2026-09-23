# Gold Wave 338: hosted role-fixture terminal repair

Group684, run `35838862993` on
`b6090b1f71ce4ca2926494b9f77389c56ecdb7d9`, source-admitted all 149 paths
and executed all 684 exact fixtures. Two retained role-fixture failures were
setup/assertion mismatches, not production role-enforcement failures.

## W296 fallback lifecycle

The first synthetic `openai_api` 429 records a durable quota backoff. The
same primary provider is therefore skipped for the later QA call, while the
distinct fallback mock handles both the primary and QA leaves. The fixture's
actual lifecycle is one primary 429 plus two fallback sends, yielding three
Left-attributed provider-request frames. Its former expectation of two primary
429 calls and four frames contradicted the production fallback cooldown
contract.

The fixture now asserts one primary call, two fallback calls, and three
Left-attributed request frames. The adjacent denied-fallback-model fixture
still requires its rejected fallback to make zero raw calls.

## W300 Cerebellum denial

The denied decomposer correctly returns an error whose outer display is the
content-free decomposer context, while the chained display contains the typed
role violation:

`role dispatch denied for cerebellum through local_ollama: provider_not_allowed`.

The assertion now inspects the existing error chain with `{error:#}`. It still
requires the role denial and retains the zero-raw-call assertion; no production
provider, policy, or dispatch behavior changed.

## Validation boundary

This is a source-only repair under the absolute local BSOD hold. No Cargo,
compiler, Rust parser, formatter, test, runtime, model, or local CI was run.
Only hosted Group684 evidence and text-level diff/search checks were used.
