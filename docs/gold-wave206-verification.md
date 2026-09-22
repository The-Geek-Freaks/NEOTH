# Wave 206 terminal refusal mirror

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

W206 adds the missing structural mirror after a replaceable direct/streamed
refusal. Right and Cerebellum run sequentially against a typed, fenced context.
Each result must contain exactly two allowlisted enum fields. The visible
explanation is rendered deterministically; provider prose and the original
request are never relayed as an attempted answer or workaround.

The prepared turn retains its shared Council call budget. Both mirror roles
also share one operation reservation for 4,000 conservative input-plus-output
tokens and USD 0.02, in addition to the configured Council daily cap. Each
provider must prove a finite output ceiling and a canonical price bound before
dispatch. Unknown bounds fail closed; known local zero-cost bounds remain
valid. Concurrent clones reserve atomically. Once admitted, an uncertain or
failed call cannot refund the operation reservation. A pre-dispatch operation
rejection releases its separate daily reservation.

Role construction and both calls share one absolute six-second deadline and
the existing turn cancellation gate. D23 is checked for every eligible mirror,
even when legacy refusal recovery is disabled. A hard block constructs no
roles and returns the deterministic terminal template. No LOWKEY, abliterated
or teacher recovery follows a terminal mirror, including an audit failure.
Already emitted live streams cannot be silently replaced.

The same-session, data-minimal REFUSAL_MIRRORED (0x17) record must be durable
before the replacement becomes visible. If that append fails, the original
refusal remains visible and subsequent recovery stays blocked.

Independent static review passed after the deadline, D23 and operation-budget
repairs. Eighteen selected source regressions cover the bounded core, typed
output rejection, cancellation/deadline, actual authorizer dispatch and daily
ledger composition, plus separate D23-disabled-recovery and exhausted-budget
chat integrations. No local build, formatter, parser, test or runtime was run
under the workstation BSOD hold. Hosted compilation, formatting and behavior
remain required; this report does not close GOLD-LF-P1-02 or a release gate.
