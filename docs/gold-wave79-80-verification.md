# W79/W80 - one outline sidecar and a Buddy change-impact action

Status: independently reviewed source, focused formatting and GUI source lint
pass. Compiled and runtime acceptance for these changes is pending GitHub CI.
Heavy Rust compilation remains suspended on the workstation.

W79 fixes duplicate output in the real authenticated MCP gate. After the actual
call/audit succeeds, the gate appends the fresh built-in outline sidecar and
omits configured enrichment only when its bytes are identical. Distinct content
keeps its order; error responses and stale/missing built-ins keep their existing
configured-enrichment behavior. No new authority, cache or cross-call state is
introduced. The real W53 child fixture now exercises a matching configured hook
and retains the one authenticated decision / one MCP-called WAL receipt checks.
A second real-child fixture checks distinct configured text.

W80 adds **Analyze change impact** to Buddy's existing menu. It opens Coding and
passes the current repository root and selected Git comparison to the existing
read-only impact controller. It does not refresh the index or call a provider.
The generated-UI fixture uses a real two-commit repository and lifecycle refresh,
then invokes the actual Buddy callback. It requires a terminal non-error receipt,
canonical root, exact `HEAD~1..HEAD`, a 64-character diff digest, positive equal
generations, one exact seed, zero observed-test rows and the non-absence warning.

Both initial proposals were blocked during review and corrected before admission:
W79 replaced a known Clippy `map_or` pattern; W80 strengthened receipt assertions
which had allowed blank generation fields. Original proposals and BLOCK reviews
remain retained in WORK. Only the approved revision-02 sources were admitted.

The [source manifest](verification/gold-wave79-80-source-manifest.json) retains
the 288-input W77 scope, with three changed source owners. The
[test matrix](verification/gold-wave79-80-test-matrix.json) carries all previous
required fixtures plus the two real MCP cases and new Buddy callback:
**47 native / 6 GUI required identities**. Earlier source passes are not relabeled
as proof of these changes.

| Evidence boundary | State |
| --- | --- |
| Independent source reviews | Both revision-02 proposals approved |
| Changed Rust formatting | Two files pass |
| GUI source token/motion lint | Pass; not a rendered GUI review |
| Real MCP/WAL and generated UI fixtures | Added/strengthened; pending remote execution |
| Prior W77 CI `35070262418` | Pinned Linux Clippy and doctests passed; broader jobs were still running at capture |
| Prior preview `35069306601` | Earlier `e6f24af8`; does not include W77/W79/W80 behavior |
| Installation, visual/accessibility and release | Not established |

GUI source/text review follows PRODUCT, DESIGN, COMPONENT_API, lint_rules and
AUDIT_CHECKLIST. Existing menu indices 0-9 are preserved; only index 10 is added.
The short label uses the current menu's tokens/components and no new motion.
The existing menu anchor changes from height minus 510px to height minus 560px;
source geometry fits eleven rows at the 600px window minimum. Actual rendered
positioning, keyboard/screen-reader behavior and target scaling remain pending,
so no complete GUI score or visual pass is claimed.

A separate source audit confirms that the normal Coding impact/test-evidence
view and read-only Doctor analysis-readiness probe already exist. Read/Grep/Glob/
Bash labels in the coding router are category hints, not native provider schemas
or executors. Provider tool execution goes through MCP admission; direct operator
`fs`/`os`/`terminal` commands retain their own boundaries. This does not close the
broader CRG-05 native-enrichment requirement by inventing a tool-name adapter.

ROAD/PROGRESS are updated together; their checkbox sequence is unchanged:
1324 total / 1015 checked / 307 open / 2 partial, raw309 / pre-tag308.
