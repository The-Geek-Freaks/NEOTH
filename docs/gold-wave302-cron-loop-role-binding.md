# W302 — retained Left origin for manual Cron and standalone loop

The manual `neoth cron run` and standalone `neoth loop run` commands both
construct their default fallback topology through the existing canonical Left
factory. W302 binds that already-selected Left provider identity to the final
`ProviderCallAuthorizer` at each caller. The generic loop engine remains
roleless: it receives the caller-bound authorizer and does not infer a role
from a model, provider name, or round label.

Manual Cron still passes every job to `cron::runner`. Jobs with explicit
provider, model, fallback, or `hemisphere_role` intent are rebuilt and bound
there under the job's declared role; W302 only binds the borrowed manual
default topology and does not replace a job role with Left.

The focused fixtures use counted raw provider leaves and WAL lifecycle frames:

- manual Cron admits the configured Left route, records one Left provider
  request, and blocks a mismatched Left policy before its raw leaf;
- standalone loop executes two rounds through the same Left-bound authorizer,
  with two counted raw leaves and two Left-bound provider request frames;
- standalone loop blocks a denied primary before raw transport and permits a
  synthetic 429 primary only long enough to record it, then blocks the
  disallowed fallback candidate before that raw leaf.

These are source changes under the local BSOD hold. No local compiler,
formatter, parser, test, runtime, or provider probe was run. Hosted formatting,
compilation, and selected-fixture execution remain required.
