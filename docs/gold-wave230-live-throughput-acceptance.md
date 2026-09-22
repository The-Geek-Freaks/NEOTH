# W230 — Explicit live-throughput acceptance selection

The literal P2-29 requirement permits throughput from real streamed tokens or
stream events, with a stable one-second window, lifecycle reset and honest
unavailable, paused and error states. The existing W162/W168 implementation
uses visible stream events per second because current providers do not supply
verified incremental token deltas. It never relabels events as tokens or
invents live values from a final aggregate.

This batch selects twelve existing native behavior tests which were absent
from the actual Grouped328 execution union despite being in the global native
inventory. Six cover the fixed 1000ms window, exact expiry, high-rate buckets,
explicit token-delta basis, monotonic time and terminal/reset lifetimes. Three
exercise the real CLI producer/control stream, authenticated content-free wire,
terminal ordering and idle interval under sustained non-visible events. Three
cover typed daemon protocol, runtime mapping and bridge sequence preservation.

The workflow adds wave230LiveThroughputAcceptance.requiredTests to its actual
selection, bringing Grouped328 to Grouped340. Native inventory remains841;
there are no duplicate identities and no production changes in this batch.

The separate GUI116 workflow already selects seven universal reducer/cursor
cases and the W162/W168 Linux callbacks for Main/Buddy projection and terminal
fences. Their native execution remains required. P2-29 stays open until the
actual selected core and GUI terminals pass with matching source bindings.
Direct terminal CLI accounting is a separate contract; this batch does not
introduce a second human-readable live display.

## Confirmed preceding batch

Grouped328 run35790281385 on aca578a0a3f35eb4cd0c4a35d6ca1265d8f2c30e
is admitted at328/328 actual passing tests. All68 source hashes, matrix,
Cargo.lock and per-case terminals match the frozen Git source. This confirms
W226 fixture repairs and all25 W227 autonomy cases. P2-12 remains open while
its GUI acceptance is pending. W229 live cluster mutation work is separate
and is not covered by this older receipt.

No local compiler, parser, formatter, test or GUI ran. Execution remains on
GitHub-hosted runners during the workstation BSOD hold. Release gates remain
independent of these focused acceptance selections.
