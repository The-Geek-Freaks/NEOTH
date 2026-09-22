# Wave 205 hosted failure repair

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
