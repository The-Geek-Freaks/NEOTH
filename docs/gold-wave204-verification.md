# Wave 204 GUI bootstrap session

**Hosted checkpoint (2026-09-22):** repairs are on main at `0e6ca107`; Grouped121 `35745827466` and Core/CLI `35745831818` are active. Preflight `35745808249` found only one formatting hunk in the new two-waiter test; its exact source-bound postimage is imported. No local formatter ran.

**W204/W205 behavior repair and W206 Hosted format (2026-09-22):** the
Grouped101 failure exposed an unchanged wizard snapshot waking its own and
other read-only long-polls. The owner now publishes only changed snapshots;
waiters require their exact session/boot and a newer sequence or terminal state.
A two-reader regression supplements the original mutation test. Ordinary serve
still rejects an incomplete home before WAL startup; its test now checks the
stable GOLD-ADAPT-OH-03 gate and actionable `neoth init` instruction.

The delegated-channel failure exposed admitted repository context being dropped
from the sub-agent bundle. Delegation now retains typed RepoContext alongside
mandatory Block D, while the final budget and retained-context audit remain
authoritative. Its original full integration assertions remain intact, with a
new focused bundle regression. Independent static review passed both repairs.
W206 is published at `4b39a208`; Preflight `35745312836` supplied six formatting
postimages verified against the exact source, receipt hashes and Git object IDs.
Fresh Hosted compile and Grouped121 behavior gates are required. No Road box
closed and no local executable validation ran.

**W204 first Hosted compile repair (2026-09-22):** source `40f2e46f` is
published on main. Grouped101 `35741899027` stopped during compilation, before
any selected behavior fixture ran: two missing generic annotations, a private
remove helper returning bool instead of unit, and four test partial moves.
The seven compiler diagnostics are repaired without changing assertions or
session behavior. Preflight `35741875989` supplied formatting for six files;
source HEAD, receipt hashes and exact Git pre/postimages were checked before
import. Code Quality `35741874933` passed. The current source needs fresh
Hosted compile, formatting and behavior checks. No local executable validation
ran; W206 remains uncommitted and Road counts stay unchanged.

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
