# W173 — retained prompt-tax measurement

Road scope: ADOPT31-D3. Source review is complete; Hosted compilation and
behavioral acceptance remain required. No Road checkbox closes on this record.

The existing final prompt-budget boundary estimates retained skill, memory,
repository-context, council and explicitly unattributed injection. Dropped or
truncated content contributes only its retained token estimate. This adds no
prompt text, routing decision, budget rule or authorization policy.

An internal SHA-256 binding covers the exact final prompt and optional system
text, with domain and length framing and a distinct absent-system marker. The
concrete provider authorizer checks that binding for both local and paid calls.
Council or MCP prompt rewrites invalidate an inherited measurement; model-only
resolution retains it. The binding is removed before the terminal ticket and
is never serialized into WAL or usage records.

Terminal provider usage carries only optional category counts. The durable
terminal audit path emits the live usage event once; earlier chat/council
publishers were removed to prevent duplicate counting. Normal projection and
WAL repair retain the same optional measurement. Old records stay unavailable;
a measured zero remains distinct. The live meter's existing lag indicator
continues to expose potentially missed events.

`neoth usage` and `neoth meter` show the estimated categories and the number of
measured terminal calls, separately from provider-reported tokens and price.
The usage table renders unavailable explicitly and shares its renderer with
the regression test. Agent-definition injection is unattributed, not guessed
to be a selected skill.

Independent rejected reviews 01–03 and approved review 04 remain under
`work/gold-20260906/wave173-next-batch/`. Review 04 SHA-256:
437D98119C5DCA4DE8F50523988E9FF05CA8E3D7F87A41B7328BE158D97A093D.
The integrated version removes one tautological Option-comparison test; actual
legacy decoding, terminal projection, meter and production rendering tests
retain the absent-versus-zero behavioral coverage.

Focused regression sources cover post-degradation retention at the final
request boundary, actual local/paid authorization tickets, changed prompt and
system text, model-only resolution, absent-versus-empty system, delegated agent
injection, terminal/WAL projection parity, legacy snapshots and CLI rendering.
They have not yet run for this source. No local compiler, formatter, parser,
test, fixture or product was executed; all executable gates belong to GitHub.

Hosted Preflight 35660482045 on cdaae0a4 requested exactly 18 formatting
hunks across six source files. They are imported from the retained GitHub log;
the source-bound receipt is FORMAT-HOSTED.json in the W173 work directory
(SHA-256 16ECA5542841BF20F78DDD1B18D7E8BBAA71E8C0873679F8B46263CDF26E6D58).
Code Quality 35660480451 passed. CLI build/reference 35660480510 remains in
progress; fresh formatting and behavioral acceptance are still required.
