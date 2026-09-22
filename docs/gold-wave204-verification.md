# Wave 204 GUI bootstrap session

**W204 daemon-owned GUI onboarding source (2026-09-22):** first-run setup now
uses `serve --wizard-bootstrap` before ordinary daemon configuration/runtime
startup. A private authenticated Unix socket or Windows pipe admits commands
through a bounded single owner; the completion token stays in the daemon and
`init/io` remains the only marker authority. The GUI retains one session,
submits its real ChannelOverride, observes coalesced sequence-bound snapshots
without holding the mutation lock, and reaches Chat only after Completed.
Prepared config hashing and completion share the canonical transaction lock.
Cancellation, stale boot/sequence, ambiguous response, daemon restart, bounded
admission, terminal response failure, and owner/PID drain have focused tests.
The native owner is joined before task-owned PID release; Guard drop never
blocks the GUI/Tokio thread. Existing Dream readback/revision behavior remains.

Independent static review passed after lifecycle repairs. Fifteen new native
identities and seven GUI identities are recorded with platform gating; their
hosted execution is pending. W204 observes full snapshots, not a lossless event
stream, and supports the existing ChannelOverride input rather than claiming
all hypothetical wizard inputs. P1-18 remains open pending hosted/native GUI
acceptance. No local build, parser, formatter, test or product runtime ran.

W205 source `aced377c` passed Preflight `35740724198` and Code Quality
`35740719898`. Prior `6bf25239` Core/CLI/export `35739731593` passed; Grouped86
`35739726969` executed86, passed85, with only the delegated-channel final-response
fixture still failing. The fixture now explicitly enables its delegated MCP catalogue, preserving the four-tool/child-scope/final-response assertions; rerun remains required. All23 W202 n8n identities passed. The
W206 mirror pipeline remains separate uncommitted work. Road counts remain
1324 total / 1015 checked / 307 open / 2 partial.
