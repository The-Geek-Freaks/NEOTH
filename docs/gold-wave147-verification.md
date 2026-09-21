# W147 - cache-only Ouro Q8 verification

The quantized Ouro layer/model and receipt-bound adapter loader already existed.
This slice adds a direct consumer and real tiny-artifact acceptance fixtures.

`neoth ouro status` reports the configured quantization mode. The explicit
`neoth ouro verify-q8` command tests Q8 independently of that setting and emits
both configured and tested modes. It resolves only an already-published
immutable cache generation. It does not download, recover or promote mutable
artifacts; the existing loader retains its platform cache-lock coordination.

The verification follows the production artifact receipt, retained load lease
and QuantizedOuroModel construction. Two fixed token sequences must produce
finite, nonempty logits with nonzero signal and distinct digests. The result
includes the artifact receipt, device, loop count and both forward digests.
It never substitutes the native model for failed Q8 construction.

The CLI observes a dedicated standard-thread worker for 120 seconds, outside
Tokio's blocking pool. A timeout returns an unsuccessful observation result
without claiming cancellation of an in-flight device call. Dropping the Tokio
runtime therefore does not wait on this verifier thread.

Four added test identities cover refusal of an unpublished cache without
promotion, two fresh real CPU Q8 loads through receipt/lease/forward with
repeatable context-sensitive digests, invalid quantized artifacts without
native-success fallback, and timeout return while a controlled worker remains
held. These are source fixtures pending GitHub-hosted execution.

The existing separate same-weight native/Q8 parity fixture remains the tolerance
oracle; this slice does not claim a new full adapter-to-native parity result.
GUI Q8 presentation and broader P1-09 runtime/progress acceptance remain open.
No Road checkbox is closed. No local compiler, formatter, parser, tests, model,
product or GUI was run. Independent source review is recorded in the matrix.

Hosted follow-up (2026-09-21): CLI-reference run 35592976685 successfully built
and exported source 3a1da19e91c4d778f950ce5ee11338a1016c1b79. The imported
reference SHA-256 is C62E540D19CA3662E30323231AE24431C8FB802FD7E29FEBA98B5ADA3852CCD6.
Preflight 35592975695 supplied exactly nine formatting hunks (four CLI, five
adapter); all nine postimages were imported and no preimages remained. Full
log SHA-256: 3980BAEF80ECF952682722C512EBF4E9523A2F8781468B7476534317BC66FC98.
Code Quality 35592975120 passed. This is CLI build/reference and source-format
evidence; the four new test identities and wider native/GUI acceptance remain pending.
