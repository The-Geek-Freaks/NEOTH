# W349 - hemisphere role-enforcement acceptance

GOLD-LF-P2-15 is accepted against 50 required role-enforcement cases and 13
supporting direct-retry cases in source-admitted Group687 run35843153480 on
571b0e032b93081292293cbf4e2fa42afeee12b7. All63 passed. The two retained
Research fixture failures do not overlap this parent contract.

The cases cover typed role policy and violations, council, normal chat,
background/direct dispatch, authorized fallback and retries, coding, cron and
sub-agents. Adversarial prompt boundaries and role-attributed actual
provider/WAL effects include denied-role zero-call cases.

docs/verification/gold-wave349-p215-acceptance.json records every executed
identity and source hash. Relevant published role source remains unchanged
through76abfed7. The only mapped-file delta consists of three hunks inside
the independently reviewed W342 architecture-test setup in cli/chat.rs,
outside both role production code and the required fixtures. Group687's
actual source bindings supersede the older W335 static hash map.

This functional acceptance leaves workspace/platform and release gates open.
Road:1324total=1027checked+295open+2partial;297raw/296pre-tag blockers.
WS-LF20done/98open. No local executable validation ran.
