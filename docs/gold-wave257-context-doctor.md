# GOLD-W257: Context Import Doctor status

`neoth doctor` includes `context import control-plane`, an observation-only
check of the authenticated daemon-owned `neoth context import status` contract.

The check calls the existing same-user authenticated Context client and parses
the connector-control writer's successful `{"ok":true,"data":…}` envelope
before reading its content-free account status. It does not read `freedom.yaml`
as a readiness signal and does not start, pause, resume, plan, import, repair,
or make any network request.

A PASS is limited to this statement: the live daemon control plane returned one
`local_import` account with `lifecycle=active` and nonzero policy and lifecycle
revisions. It does not claim that an import was attempted, accepted, or
succeeded.

Paused and revoked accounts are WARN and explicitly unavailable. An unavailable
daemon endpoint, discovery or transport failure is WARN with readiness unknown.
Missing Local Import status is WARN. Malformed status, duplicate Local Import
accounts, an unknown lifecycle, or zero revisions is FAIL and never treated as
ready.

The current status contract has no timestamp, heartbeat, expected revision, or
other temporal freshness field. Doctor therefore reports the live status it
received but does not infer a temporal `stale` condition from revision numbers
alone. A future stale diagnosis requires an independently defined expected
revision or a status-contract freshness field with documented semantics.
