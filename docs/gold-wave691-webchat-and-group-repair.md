# Authenticated loopback WebChat and grouped fixture repairs

The new `neoth companion webchat` command asks the running daemon's same-user
audit RPC for a short-lived, one-use handoff URL. The existing Companion listener
serves the page and its API; minting is unavailable until that listener is bound,
and listener shutdown revokes readiness. A Companion pairing token does not grant
WebChat authority. The browser clears the URL fragment before API requests and
uses a separate HttpOnly session cookie. Handoffs, sessions, request counts,
request body size and transcript projection are bounded.

Each browser session uses a server-generated session ID and UUIDv7 request IDs.
Preflight and consent decisions use the existing chat runtime and request-bound
proofs. Turn start, replay and cancellation capabilities remain server-side.
Repeated decisions and starts preserve their original result; another session's
request ID is refused before runtime work. Native Main/Buddy and WebChat attach
authority remain separate. Browser polling advances its replay cursor without
weakening the native streaming subscription cursor check.

The page supports send, Allow once / Deny, stop, bounded saved transcript and
cookie-based reconnect. A reconnect invalidates in-flight preparation before it
can start a stale request. Provider text is rendered as text. Existing corrupt or
oversized transcript storage produces a visible error instead of an empty
success. Missing storage and older storage without raw turns remain empty.

W691 adds nine native behavior tests: six actual HTTP gateway fixtures, two real
runtime replay/authority fixtures and a real Companion listener readiness test.
Seven Chromium tests execute the actual shipped page against a controlled API
fixture in the separate `WebChat browser contracts` workflow. These browser tests
are not evidence of a live provider turn through the packaged daemon.

Independent static review was clear. Root then corrected a replay mutability
error and the reconnect race before publication. All executable validation is
pending on GitHub. The local BSOD hold remains absolute; no local compiler,
formatter, test, browser, model or product runtime was used.

## Group1060 evidence and W693/W694 repairs

Run35966268023 at db1d9758b0d6bd485b78dc3b699ad7e3131e0b8b executed all1060
selected tests:1054PASS,6FAIL,0missing. Root verified the three artifact ZIPs,
201 source/input Gitblob bindings and every ordered test identity and terminal.
See `verification/gold-wave692-group1060-terminals.json`.

Three Slack test fixtures used invalid member IDs containing hyphens. Their
canonical alphanumeric replacements preserve the production validator and
behavior assertions. Three dispatcher/Cron fixtures now explicitly use strict
delivery, the matching routing source plus a home-ready WAL writer, and Full
autonomy with no Telegram credentials. Assertions remain unchanged. The new
keychain-refusal file-lifecycle test passed in Group1060. Repaired cases await
the next hosted run; no full Group pass is claimed.

W689's exact hosted formatting patch for the dispatcher was imported before the
fixture repairs. Its receipt is `verification/gold-wave689-hosted-format.json`.
The selected grouped inventory grows to1069 and portable native inventory1339.
The new CLI export must be imported before Group1069 runs. GUI/Buddy onboarding,
migration, remaining WebChat parity and named proactive Slack delivery retain
their existing Road status. No roadmap checkbox closes from this publication.

Claude's RESULT-001 informed the previous Slack identity repairs. TASK-002 asks
for workspace binding across token rotation; its result is still pending.
Additional research is read from the collaboration folder and triaged against
existing work before adoption; queued research is not implementation evidence.
