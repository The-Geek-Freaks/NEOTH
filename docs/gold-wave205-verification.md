# Wave 205 hosted failure repair

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

**W205 Hosted formatting follow-up (2026-09-22):** source `6bf25239` is on
GitHub main. Preflight `35739707562` exported exactly two formatting hunks;
source HEAD, receipt SHA-256 and full Git pre/postimage identities were checked
before import. The new source-scan collector is inlined at its sole caller to
avoid an eight-argument wrapper while preserving both audits and diagnostics.
Core test-target checking in `35739731593` has passed; public CLI build and
Grouped86 `35739726969` are still active. Code Quality `35739707200` passed.
W204 and W206 remain separate uncommitted work. Road counts stay unchanged.

**W205 Windows fixture contracts / W202 HTTP framing repair (2026-09-22):**
Hosted Grouped83 `35737278608` on `9024b7db` executed all 83 identities: 81
passed, including the strict Cron WAL event-link regression. The two remaining
n8n failures share a mock HTTP framing error: a 29-byte documented JSON body
advertised 28 bytes. Only five fixture headers are corrected; production
validation stays strict. All actual names, source bindings, matrix and lockfile
hashes were checked against the downloaded evidence. The same source passed
Preflight `35737276826` and Code Quality `35737276710`.

The completed older full matrix `35726117022` recorded nine Windows failures
among 17,334 cases and an active macOS compile timeout. W205 fixes four distinct
fixture/inventory contracts: canonical physical materializer path, WAL HMAC
initialization before authenticated installation, explicit Research CLI parity
triage, and the reviewed authorized Research provider-call digest. Independent
static review passed; hosted behavior is pending. Three exact identities join
the grouped selection (86 total); the materializer identity was already selected.
The outbound-source scan now shares each parsed source between both existing audits instead of reparsing the tree repeatedly; its 120-second Windows limit and every check remain unchanged. This performance repair still requires hosted confirmation. Previously repaired
local-model uncertainty, Research budget presence, Drawio routing and WAL-join
issues remain subject to fresh full CI. W204 wizard work remains uncommitted.
Road remains 1324 total / 1015 checked / 307 open / 2 partial. No local compiler,
parser, formatter, tests or product runtime ran.
