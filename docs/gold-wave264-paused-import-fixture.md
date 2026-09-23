# W264 — Paused Context Import is a client refusal

Group44185c (35808222289, source85c87f57) executed all441 selected fixtures:
440 passed. Its single failure was the actual Unix Context Import roundtrip,
after successful Status, Plan, Apply and Pause, at the attempted paused Plan.
The daemon correctly returned HTTP422. The Unix client intentionally refuses
non-200 responses before exposing the body; the test incorrectly expected an
Ok string containing the rejection JSON. Windows has the same assertion bug
against its own existing non-200 refusal contract.

Both platform fixtures now expect the actual client error. They still require
the exact persisted paused revision before that refusal, then resume, recover
the lifecycle, stop the listener and reopen the accepted import outcome. No
production HTTP/client/lifecycle behavior changes and no rejection is converted
to success. Unix checks the exact HTTP422 refusal; Windows checks its existing
fixed rejection message. A new hosted execution is required to prove the steps
after the previously failing assertion.

Root verified all93 grouped source paths, the matrix and lock, and all441
individual terminals. The W256 five search, W257 four Doctor and W258 socket
fixture cases passed. This scope does not close CC-04 or establish macOS/Windows
live acceptance. No local executable validation ran under the BSOD hold.
