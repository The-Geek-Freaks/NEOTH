# W179: Hosted prompt-layer Clippy repair

CI run `35667842810` at `a72b403846f512b67b7bc05e751f6b7e2d667c61`
reported two `clippy::type_complexity` errors in the slim-core Linux job
`106557462709`. Both refer to the same four-part prompt-layer tuple, in the
eight-element array before attachments and the three-element array after them.

The repair gives that exact tuple the private alias `EnrichedLayer<'a>`.
Both array annotations use the alias; tuple values, order, array lengths,
degradation behavior and prompt-tax provenance remain unchanged. No lint is
suppressed. Root reviewed the complete three-hunk diff against the Hosted log.

Source SHA-256:
`72A8D3A89E93821548855FC332208B448EDA99AB9325501157BAC40C03520BDD`.
Hosted log SHA-256:
`57BFA962837FAB099F93E43701F191F6ED74134839AD2C996758EB808365E1EC`.
Repair receipt: `work/gold-20260906/wave179-hosted-repair/CLIPPY-REPAIR.md`,
SHA-256 `0C914F6D4EC0763B12B03753DF7023DB7B749A04E9C57160E0986F805BDAB8A8`.

Preflight `35667753310` and Code Quality `35667752599` passed on a72b4038.
The same-source full CI passed Gold smoke and several component jobs, while
Windows and macOS test compilation remained active when this repair was
prepared. The active native jobs are retained to collect their actual results;
a source push does not replace their source identity or establish new-source
acceptance. A fresh Hosted Clippy result is still required for this repair.

The separate W177 training-export implementation remains unadmitted. Its dirty
source hashes are excluded from this publication. No local compiler, parser,
formatter, test, fixture or product ran. No Road checkbox closes.
