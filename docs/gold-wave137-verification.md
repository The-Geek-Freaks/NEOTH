# W137 — retained skill sessions and real channel delegation

This batch adds three acceptance tests and strengthens three existing tests.
Its two source files passed independent static review; native execution is
still required. It does not close GOLD-LF-P2-10 or change Road counts.

The CLI fixture installs and authorizes Skill generation A, publishes B from
the first refused provider call, and drives the real prepared-turn pipeline.
Cloud retry and local-shadow recovery retain A's body and complete registry
envelope. Cloud retry also retains its model and effort budget. A new turn
resolves B. Disabled and authority-rejected bodies never enter the requests.
The provider request does not expose the internal tool scope, so this fixture
does not claim a direct tool-scope observation.

Channel retry and fallback now assert the complete parsed registry envelope.
The two-account fixture uses distinct authenticated account bindings and
accepted configurations: a disabled skill never reaches that account's
provider, while the independently allowed account routes it. This is evidence
of account/config-policy isolation, not a subject-keyed registry under one
identical configuration.

The delegation fixture installs and authorizes a real skill, loads its agent
TOML, and drives handler, provider, MCP loop and a real CodeGraph child. Only
the tool shared by both allowlists reaches the child. Skill-only, agent-only
and explicitly forbidden tools each have their own canonical ToolError
envelope with the exact server/tool/status=SCOPE_DENIED binding. The delegated
prompt retains its required session registry and attachment context.

Admission uses frozen source copies to exclude ongoing W138 autonomy edits:

- chat_turn_pipeline.rs: `0A4068F6E26BC4D8E7FE314C53C78FC242DD618BD183696822B6F8EA734505D2`
- serve_pipeline.rs: `C958C1B8C276B6C1FD5DE1AB85CE21A65A547017A6C0A1D093FB7B0EB5AA4871`
- Independent review: `7A55EFEA1DA076E495E2A0FFC18B84851BB2A83FA719BDA59E6BCDF6B37666AC`

The cumulative matrix records 308 source inputs and 142 required native test
identities, including the newly required delegated-bundle assertion. Existing
GUI and optional adapter test sets are unchanged. No local compiler, formatter,
parser, test, fixture, product or GUI was run.

The preceding source 12048d6c passed Preflight 35581470771 and Code Quality
35581470537. Full CI 35581691195 passed Gold smoke and several component jobs,
but its Linux quality job reported four strict Clippy diagnostics in
code_map/type_hierarchy.rs. W140 addresses those observed diagnostics;
that run is not W137 runtime proof. Windows preview 35575775478 is on older
85658d48 and cannot establish current-source acceptance.

## Hosted formatting follow-up

Preflight35583073252 on28b9facd supplied ten Rustfmt hunks, imported
from the complete saved log (two CLI/eight Channel). Independent import and
Root review confirm layout/trailing-comma normalization only. The formatted
source hashes are CLI034F4C9AC374F29A470EBE9853DC7AD374D1420BC2C758EF11E21350526701C9
and Channel95BEBF390875D5649116652D43DBDB67F0F303EB2A2503D5A099A02D08EB714A.
CodeQuality35583072869 passed before this formatting import. Fresh exact-head
hosted validation remains required; no local formatter ran.
