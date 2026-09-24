# Slack workspace binding and hosted fixture corrections

W712-W714 applies Claude Desktop RESULT-002's verified source finding: the
candidate Slack auth.test response already contained an immutable team_id, but
add/rotation discarded it. The CLI now retains the observed canonical Team ID
from the exact prepared bot token and supplies it to the existing paired-file
commit. Both retained raw file snapshots must still match before publication.

The final public policy is rendered under that CAS boundary. A same, previously
known workspace preserves an existing account incarnation. New, unknown,
cross-workspace, or missing-incarnation records receive a fresh incarnation.
Legacy migration keeps workspace identity explicitly unknown until a subsequent
successful probe; no override can preserve unknown workspace authority. Both
Slack tokens and unrelated account/extension fields remain preserved.

Read-only channel test keeps its public result schema. For a known stored Team
ID it now refuses a successful auth.test reporting a different, absent, or
malformed Team ID. Legacy-unknown accounts keep their earlier authentication
probe behavior. Add/rotation intentionally accepts a different observed Team ID
and commits a new incarnation. The Slack runtime reload fingerprint and health
binding include workspace identity with a new v2 domain, so only the affected
account's old runtime view is retired. No external Slack message was sent.

Seven added regressions cover storage authority reuse/replacement, invalid
observation without writes, old known-team records without an incarnation,
exact probe-to-persistence custody, known-team read-only mismatch, historical
compatibility and per-account runtime invalidation. The existing exact-account
CLI test gained observed-team persistence assertions. W710 contributes two more
configuration-to-onboarding tests: portable native1360 / Group1090.

W715 independently admits Group1081 run35973525383 at59e2d5eb:1079PASS/2FAIL,
all1081 executed, all204 fixture-source and2 input bindings and exact terminals
verified. All new W691/W706 WebChat and CUA cases pass, including actual producer
session custody, Incognito persistence suppression and live RPC readiness.
W716 fixes the two remaining fixture defects: strict Cron failure independently
enqueues a hermes_07 self-heal alert, so its test now distinguishes that alert
from the forbidden cron:delivery-job admission; the recovery WAL fixture now
uses the required home/wal/000001.wal path. Production gates remain unchanged.

W717 admits Core35973521304 at59e2d5eb: slim Clippy, test-target checking, CLI build
and generated-reference export pass. The exact exported reference remains
unchanged. See verification/gold-wave715-group1081.json and
verification/gold-wave717-core-cli.json.

Independent source review passes the new Slack/onboarding changes and fixture
corrections. Their new hosted execution is pending. No local compiler, formatter,
parser, test, driver or product runtime was run. Named Slack proactive DM delivery
is still a separate P1-14/P1-16 residual; this prerequisite does not claim it is
implemented. No Road checkbox closes in this batch.
