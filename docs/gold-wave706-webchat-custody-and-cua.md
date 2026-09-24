# WebChat session custody, readiness and CUA compatibility

W700-W705 complete two concrete gaps found while integrating the loopback
WebChat. The browser's sealed session ID now reaches the existing daemon chat
producer before preparation chooses its session identity or displays a hindsight
banner. WAL attribution, recall and persisted operator/agent turns therefore use
the same admitted session. Incognito retains a transient generated identity.
The new real-producer fixture sends two ordinary turns to distinct sessions and
one Incognito turn, then checks both actual saved pairs, exactly four total raw
rows and no Incognito prompt anywhere. It inserts no transcript fixture rows.

Reconnect now asks the runtime whether a stored request has actually completed,
so a completed ordinary turn is shown from its saved transcript rather than
replayed as another active response. An unpolled completed Incognito turn remains
available for transient replay. The gateway first exchanges its stored
same-session grant for a server-only attach capability; the real start response
deliberately contains an empty origin capability. Real-runtime and HTTP tests
cover this distinction, session isolation and capability-free browser responses.

`neoth status` now includes a separate WebChat result. It distinguishes unknown
configuration, disabled configuration, an unready listener, a ready endpoint and
an unreachable daemon. Its read-only RPC uses the existing authenticated local
transport and never mints a handoff. A real listener/child-client fixture checks
unready, ready and absent states through the public client, including the existing
cross-platform PID-lock semantics. The enabled-without-daemon CLI projection is
also covered. These tests replace the earlier hand-constructed table examples.

WebChat uses the existing Companion listener. Enable `companion.enabled` in the
daemon configuration, start `neoth serve`, then run `neoth companion webchat`
as the same local user and open its one-use URL. The status endpoint contains no
session token. Its base URL alone is not a pairing URL. This slice still does not
close the broader account, GUI/Buddy onboarding, migration or WebSocket parity
requirements in GOLD-LF-P1-15.

## Claude R04: verified CUA compatibility repair

Claude identified stale computer-use tool names. The exact upstream contract at
6762bcf63b616c6de86ab7b2309686150913105b was independently fetched and its Git
blob and SHA-256 checked. It contains29 tools, with three names shared with the
existing NEOTH list. The accepted repair retains the11 historical names and adds
seven observed equivalents. The ten current verbs do not admit the other19
upstream verbs. Clipboard, session escalation and unrelated driver controls stay
outside the default allowlist. See `verification/gold-wave702-cua-contract.json`.

Explicit `computer-use enable` updates only the exactly recognized previous
generated configuration. Custom commands, arguments, environment, allowlists
and gates remain operator-owned. Doctor reads the actual saved configuration,
distinguishes missing capability groups from optional spelling aliases, and
keeps its existing raw `missing` JSON field. Its full-trust and deny-by-default
diagnostics follow the actual MCP gate. PATH version metadata is labelled
separately from the configured command it probes. No local driver was run.

## Evidence boundary

Independent source review passed after the producer, reconnect, status and
Doctor corrections. Twelve selected behavior tests extend portable native1351
and Group1081. Executable validation of these changes is pending on GitHub.
No local compiler, formatter, parser, driver, test or product runtime was used.

The preceding WebChat source18ff87aa completed Core run35969533176: slim-core
Clippy, test-target type-check, public CLI build and generated reference export
all passed. Root imported that exact249367-byte reference with SHA-256
4445f7b2fa74fb54eb62d8841085ee757e12d6f33ab46aa30c4c4c9b1b0b18c8;
see `verification/gold-wave704-core-cli-reference.json`. Its seven hosted browser
tests also passed. These earlier results do not claim execution of the new
producer/status/CUA tests or a live installed driver. No roadmap box is closed
by this publication.
