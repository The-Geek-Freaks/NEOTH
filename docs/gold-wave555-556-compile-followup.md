# W555-W556: hosted compile and format follow-up

The complete hosted GUI148 run 35929972686 at source
6146f6a4becf780a035e087aa4ac4f15d07284bf executed all 148 selected fixtures:
145 passed, three failed. Root retained the source, receipt and logs under
work/gold-20260906/wave554-gui1486146; full evidence admission is pending.

## P118 diagnosis remains open

The cancellation fixture fails its frozen Finish status assertion; the daemon-loss
fixture fails earlier because a retained descriptor is still discoverable.
The first proposed test-only change was rejected during independent review.
No corrected P118 behavior or acceptance is claimed.

## Compile correction (W555)

The dedicated Google Chat run 35933359541 at cf72159e stopped before test discovery:
E0382, `paperless_staging.rs`, displaced PathBuf moved into the publication-swap
closure then reused by the final directory assertion. Clone the closure-owned
path and retain the original for the assertion. This is a fixture lifetime fix;
no GChat behavior was executed or accepted from that run.

## Hosted formatting (W556)

Preflight 35933358886 at cf72159e emitted artifact10781713431, ZIP SHA256
`afcefac107ab67d87582aac332b177082752f4580473f1bd68a9ccd0d311bde8`.
Root verified source-head, both SHA256SUMS entries, all six before Git blobs,
patch applicability and all six exact after Git blobs before the W555 edit.
The retained admission is work/gold-20260906/wave556-formatcf72/ADMISSION.json.
No local formatter ran.

## Historical SQL failures (W553 scout)

FullCI35871801240 at bc9db76c had seven shared Windows/macOS SQL failures.
The unqualified JOIN ordering `transport_identity` was ambiguous. Commit
d0833c063db2845dd442bd8121bc7439cb02e9dc qualified `o.priority` and
`o.transport_identity`; cf72159e retains that fix. Treat the old error as source
superseded, not as newly passing behavior. The separate browser and WAL failures
are outside this diagnosis.

## Evidence boundary

No new Road checkbox closes. Road remains1044checked/278open/2partial;
WS-LF37done/81open. Native1215+Windows25/Linux36/macOS35; Group934 plus
four separate GChat-feature cases; GUI148Linux/144macOS. Root performs final
source-binding admission and updates the checkpoint when hosted evidence arrives.
Absolute local BSOD hold and Slint hold remain in force.
