# W148 - hosted lib-test binding repair

Full CI 35590346071 on e2de082a exposed E0425 in
providers::cost_authorization::tests::pinned_retry_cannot_bypass_a_denied_paid_call_gate.
The channel-adapters job 106303075769 compiled production code, then failed
while compiling lib-test because the local binding was named `_error` while
the existing assertion referenced `error`.

The one-line source repair names that binding `error`. The custom-override
error assertion and zero-provider-call assertion are preserved. Root reviewed
the complete hosted diagnostic and exact one-line diff. The complete log is
retained in work/gold-20260906/wave148-adapter-hosted-repair.

Fresh GitHub-hosted compilation and runtime are required. No local compiler,
formatter, parser, test, fixture, product or GUI was run. W142/W147 working
changes are excluded. No Road checkbox is closed.
